import gdb
import re
import json
import binascii
import os
import sys
import socket
import struct

config = None
with open("config.json", "r") as fp:
    config = json.loads(fp.read())


tracer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tracer_sock.connect(("127.0.0.1", int(config['fuzzer-gdb-port'])))
tracer_sock.send("ok")

tracer_sock.recv(4)

BB_LIST = []
PROCESS_MAPS = None
COV_MODULE_INFO = {}
COV_MODULE_INFO['module_name'] = config['coverage_module_name']

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
    global PROCESS_MAPS, BB_LIST
    print(status)

    if status == "crash":
        save_crash_info()

    gdb.events.exited.disconnect(exit_handler)
    gdb.events.stop.disconnect(stop_handler)
    
    save_bb_trace(status, BB_LIST)
    print("[trapfuzzer] save_bb_trace {}".format(status))

    del BB_LIST
    BB_LIST = []
    PROCESS_MAPS = None

    gdb.events.exited.connect(exit_handler)
    gdb.events.stop.connect(stop_handler)


def save_bb_trace(status, bb_list):
    data = ""
    for bb in bb_list:
        data += "{:X},".format(bb)

    with open("gdb.trace", "w") as fp:
        fp.write(status + "\n")
        fp.write(data[:-1] + "\n")

    print("******** {} ********\n".format(data))
    

def save_crash_info():
    reg_info = gdb.execute("i r",to_string=True)
    instr_info = gdb.execute("x/i $pc",to_string=True)
    bt = gdb.execute("bt 6",to_string=True)
    with open("gdb.crash", "w") as fp:
        fp.write(reg_info + "\n")
        fp.write(instr_info + "\n")
        fp.write(bt + "\n") 


def exit_handler(event):
    print(event)
    save_and_data_exit("normal")


def write_memory(address, buffer, length=0x10):
    return gdb.selected_inferior().write_memory(address, buffer, length)


def get_pid():
    return gdb.selected_inferior().pid


def read_memory(addr, length=0x10):
    return str(gdb.selected_inferior().read_memory(addr, length))


def stop_handler(event):
    global BB_LIST, PROCESS_MAPS, COV_MODULE_INFO, EXIT_BB_LIST, Log

    print event

    if isinstance(event, gdb.SignalEvent):
        if event.stop_signal in ["SIGABRT", "SIGSEGV"]:
            save_and_data_exit("crash")
        elif event.stop_signal == "SIGINT":
            save_and_data_exit("normal") 
    elif isinstance(event, gdb.StopEvent):
        if PROCESS_MAPS is None:
            print("read {} maps".format(get_pid()))
            PROCESS_MAPS = read_maps(get_pid())
            for m in PROCESS_MAPS:
                if m.pathname and COV_MODULE_INFO['module_name'] in m.pathname:
                    COV_MODULE_INFO['image_base'] = m.start
                    COV_MODULE_INFO['full_path'] = m.pathname
                    with open("config.json", "w") as fp:
                        config['coverage_module_full_path'] = m.pathname
                        fp.write(json.dumps(config))
                    break

        pc = get_register("$pc") - 1
        offset = pc - COV_MODULE_INFO['image_base']

        print("offset: 0x{:X}\n".format(offset))

        # exec to exit point
        if offset in EXIT_BB_LIST:
            save_and_data_exit("normal")

        try:
            tracer_sock.sendall(struct.pack("<I", offset))
            raw_byte = tracer_sock.recv(1)
        except Exception as e:
            print("gdb.trap: {}, 0x{:X}".format(e, offset))
            print(event.stop_signal)
            print(dir(event))
            return
            
        write_memory(pc, raw_byte, 1)
        set_register("pc", pc)

        BB_LIST.append(offset)
    else:
        pass

gdb.events.exited.connect(exit_handler)
gdb.events.stop.connect(stop_handler)

with open("gdb.pid", "w") as fp:
    fp.write("{}\n".format(os.getpid()))

