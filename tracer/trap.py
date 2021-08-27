import gdb
import re
import json
import binascii
import socket
import sys
import struct
import os

DEBUG = False

config = None
with open("config.json", "r") as fp:
    config = json.loads(fp.read())


tracer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tracer_sock.connect(("127.0.0.1", int(config['fuzzer-gdb-port'])))
tracer_sock.send(b"ok")
tracer_sock.recv(4)

if DEBUG:
    print("sever init")


BB_LIST = []
PROCESS_MAPS = None
COV_MODULE_INFO = {}
COV_MODULE_INFO['module_name'] = config['coverage_module_name']


module_trace_list = []

idx = 0
for mi in config['module_info_list']:
    # print(mi[0])
    i = {}
    i['module_name'] = mi[0]
    i['rva_size'] = mi[1]
    i['image_base'] = 0
    i['image_end'] = 0
    i['mod_idx'] = idx
    i['bbl-list'] = []
    module_trace_list.append(i)

    idx += 1


EXIT_BB_LIST = []

for bb in config['exit_basci_block_list'].split(","):
    if bb.strip() == "":
        continue
    EXIT_BB_LIST.append(int(bb.strip(), 16))

PROC_MAP_REGEX = re.compile(
    # Address range: '08048000-080b0000 '
    r'([0-9a-f]+)-([0-9a-f]+) '
    # Permission: 'r-xp '
    r'(.{4}) '
    # Offset: '0804d000'
    r'([0-9a-f]+) '
    # Device (major:minor): 'fe:01 '
    r'([0-9a-f]{2,3}):([0-9a-f]{2}) '
    # Inode: '3334030'
    r'([0-9]+)'
    # Filename: '  /usr/bin/synergyc'
    r'(?: +(.*))?')


class MemoryMapping(object):
    def __init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.major_device = major_device
        self.minor_device = minor_device
        self.inode = inode
        self.pathname = pathname


def read_maps(pid):
    maps = []
    with open("/proc/{}/maps".format(pid), "r") as fp:
        for line in fp:
            line = line.rstrip()
            match = PROC_MAP_REGEX.match(line)
            if not match:
                raise Exception("Unable to parse memory mapping: %r" % line)
            mm = MemoryMapping(
                int(match.group(1), 16),
                int(match.group(2), 16),
                match.group(3),
                int(match.group(4), 16),
                int(match.group(5), 16),
                int(match.group(6), 16),
                int(match.group(7)),
                match.group(8))
            maps.append(mm)
    return maps


def to_unsigned_long(v):
    t = gdb.lookup_type("unsigned long")
    return int(v.cast(t))


def get_register(regname):
    """Return a register's value."""
    try:
        value = gdb.parse_and_eval(regname)
        return to_unsigned_long(value)
    except gdb.error as e:
        print(e)
        assert(regname[0] == '$')
        regname = regname[1:]
        try:
            value = gdb.selected_frame().read_register(regname)
        except ValueError:
            return None


def set_register(regname, value):
    cmd = "set ${}={}".format(regname, value)
    gdb.execute(cmd)


def save_and_data_exit(status):
    global tracer_sock
    if status == "crash":
        save_crash_info()

    save_bb_trace(status)
    tracer_sock.close()
    gdb.execute("quit")

def save_bb_trace(status):
    global BB_LIST, module_trace_list

    with open("gdb.trace", "w") as fp:
        fp.write(json.dumps(module_trace_list))

    with open("gdb.status", "w") as fp:
        fp.write(status + "\n")
    
    print("[trapfuzzer] save_bb_trace {}".format(status))

def save_crash_info():
    reg_info = gdb.execute("i r",to_string=True)
    instr_info = gdb.execute("x/i $pc",to_string=True)
    bt = gdb.execute("bt 6",to_string=True)
    with open("gdb.crash", "w") as fp:
        fp.write(reg_info + "\n")
        fp.write(instr_info + "\n")
        fp.write(bt + "\n")

    with open("stacktrace.txt", "w") as fp:
        fp.write(bt + "\n")

def exit_handler(event):
    save_and_data_exit("normal")

def nop(event):
    pass

def write_memory(address, buffer, length=0x10):
    return gdb.selected_inferior().write_memory(address, buffer, length)

def get_pid():
    return gdb.selected_inferior().pid

def read_memory(addr, length=0x10):
    return str(gdb.selected_inferior().read_memory(addr, length))

def stop_handler(event):
    global COV_MODULE_INFO, BB_LIST, PROCESS_MAPS, EXIT_BB_LIST, tracer_sock, DEBUG,module_trace_list
    if DEBUG:
        print(event)

    if isinstance(event, gdb.SignalEvent):
        if event.stop_signal in ["SIGABRT", "SIGSEGV"]:
            gdb.events.exited.disconnect(exit_handler)
            save_and_data_exit("crash")
        elif event.stop_signal == "SIGINT":
            gdb.events.exited.disconnect(exit_handler)
            save_and_data_exit("normal")
    
    elif isinstance(event, gdb.StopEvent):
        pc = get_register("$pc") - 1

        hit_mod = None
        for mt in module_trace_list:
            if pc > mt['image_base'] and pc < mt['image_end']:
                hit_mod = mt
                break

        if hit_mod is None:
            if DEBUG:
                print("read {} maps".format(get_pid()))

            PROCESS_MAPS = read_maps(get_pid())
            for m in PROCESS_MAPS:
                if m.pathname:
                    if DEBUG:
                        print(m.pathname)
                    for mt in module_trace_list:
                        if mt['image_base'] == 0 and mt['module_name'] == os.path.basename(m.pathname):
                            mt['image_base'] = m.start
                            mt['image_end'] = m.start + mt['rva_size']
                            mt['full_path'] = m.pathname

            for mt in module_trace_list:
                if pc > mt['image_base'] and pc < mt['image_end']:
                    hit_mod = mt
                    break
        
        if hit_mod is None:
            print("unknown module pc trigger sigtrap!")
            save_and_data_exit("normal")

        offset = pc - hit_mod['image_base']
        
        if DEBUG:
            print("offset: 0x{:X}".format(offset))

        # exec to exit point
        if offset in EXIT_BB_LIST:
            gdb.events.exited.disconnect(exit_handler)
            save_and_data_exit("normal")

        mod_idx = mt['mod_idx']
        tracer_sock.sendall(struct.pack("<b", mod_idx) + struct.pack("<I", offset))
        raw_byte = tracer_sock.recv(1)

        write_memory(pc, raw_byte, 1)
        set_register("pc", pc)
        mt['bbl-list'].append(offset)
    else:
        print("Unknown event {}".format(event))


target_pid = None

def new_objfile_handler(event):
    global target_pid
    if not target_pid:
        target_pid = get_pid()
        with open("target.pid", "w") as fp:
            fp.write("{}\n".format(target_pid))


gdb.events.exited.connect(exit_handler)
gdb.events.stop.connect(stop_handler)
gdb.events.new_objfile.connect(new_objfile_handler)

with open("gdb.pid", "w") as fp:
    fp.write("{}\n".format(os.getpid()))