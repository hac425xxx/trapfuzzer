#!/usr/bin/python

import os
import Queue as queue
import re
import shlex
import struct
import subprocess
import sys
import threading
import time

PYTHON3 = sys.version_info >= (3, 0)

# breakpoint types
BREAKPOINT_NORMAL = 1
BREAKPOINT_UNRESOLVED = 2
BREAKPOINT_HARDWARE = 3
BREAKPOINT_SYMBOLIC = 4

# cpu types
CPU_X86 = 1
CPU_X64 = 2

# marker for prompt
COMMAND_FINISHED_MARKER = "CMDH@ZF1N1SH3D"

# max buffer size for output
OUTPUT_BUF_MAX = 5 * 1024 * 1024

DEBUG_INOUT = False


def get_arch():
    """
    Return either 32 or 64
    """
    return struct.calcsize("P") * 8


def parse_addr(addrstr):
    """
    parse 64 or 32-bit address from string into int
    """
    if addrstr.startswith('??'):
        return 0
    return int(addrstr.replace('`', ''), 16)


def addr_to_hex(address):
    """
    convert an address as int or long into a string
    """
    string = hex(address)
    if string[-1] == 'L':
        return string[:-1]
    return string


class PyCdbException(Exception):
    pass


class PyCdbInternalErrorException(PyCdbException):
    def __init__(self, output=None):
        self.output = output

    def __str__(self):
        return "PyCdbInternalErrorException: %s" % self.output


class PyCdbPipeClosedException(PyCdbException):
    def __init__(self, output=None):
        self.output = output

    def __str__(self):
        if not self.output or len(self.output) == 0:
            return "cdb pipe is closed"
        else:
            return "cdb pipe is closed: last message was: %s" % self.output


class PyCdbTimeoutException(PyCdbException):
    pass


class AttrDict(dict):
    def __getattr__(self, key):
        return self[key]

    def __setattr__(self, key, value):
        if self.setterCallback:
            self.setterCallback(key, value)
        else:
            self[key] = value


class CdbEvent(object):
    pass


class InternalErrorEvent(CdbEvent):
    def __init__(self, output):
        self.output = output

    def __str__(self):
        return "InternalErrorEvent: %s" % self.output


class OutputEvent(CdbEvent):
    def __init__(self, output, closed=False):
        self.output = output

    def __str__(self):
        return "OutputEvent: %s" % self.output


class PipeClosedEvent(CdbEvent):
    def __str__(self):
        return "PipeClosedEvent"


class DebuggerEvent(CdbEvent):
    def __init__(self):
        self.pid = 0
        self.tid = 0
        self.description = ''

    def set_base(self, pid=None, tid=None, desc=None):
        if type(pid) == str:
            pid = int(pid, 16)
        if type(tid) == str:
            tid = int(tid, 16)
        self.pid = pid
        self.tid = tid
        self.description = desc

    def __str__(self):
        return "DebuggerEvent(%x,%x)" % (self.pid, self.tid)


class LoadModuleEvent(DebuggerEvent):
    def __init__(self, module, base):
        super(LoadModuleEvent, self).__init__()
        self.module = module
        self.base = base

    def __str__(self):
        return "LoadModuleEvent(%x,%x): %s, %08X" % (self.pid, self.tid, self.module, self.base)


class BreakpointEvent(DebuggerEvent):
    def __init__(self, bpnum):
        super(BreakpointEvent, self).__init__()
        self.bpnum = bpnum

    def __str__(self):
        return "BreakpointEvent(%x,%x): %u" % (self.pid, self.tid, self.bpnum)


class ExitProcessEvent(DebuggerEvent):
    def __init__(self, exit_code):
        super(ExitProcessEvent, self).__init__()
        self.exit_code = exit_code

    def __str__(self):
        return "BreakpointEvent(): %u" % self.exit_code


class ExceptionEvent(DebuggerEvent):
    """
    class that represents an exception raised in the debuggee, such
    as an access violation. not to be confused with a python exception
    """

    def __init__(self, address, code, description):
        super(ExceptionEvent, self).__init__()
        self.address = address
        self.code = code
        self.description = description
        self.params = []
        self.details = ""
        self.fault_addr = None

    def __str__(self):
        s = "ExceptionEvent(%x,%x): %08X: code=%08X: %s" % (
            self.pid, self.tid, self.address, self.code, self.description)
        if self.details:
            s += ": " + self.details
        return s


class BreakpointInfo(object):
    def __init__(self, num, name, flags, enabled, resolved, address):
        self.num = num
        self.name = name
        self.flags = flags
        self.enabled = enabled
        self.resolved = resolved
        self.address = address

    def __str__(self):
        s = "Breakpoint #%u: %s (%s: %s,%s)" % (self.num, self.name,
                                                self.flags,
                                                "enabled" if self.enabled else "disabled",
                                                "resolved" if self.resolved else "unresolved")
        if self.address:
            s += " @ %08X" % self.address
        return s


class CdbReaderThread(threading.Thread):
    def __init__(self, pipe):
        super(CdbReaderThread, self).__init__()
        self.setDaemon(True)
        self.queue = queue.Queue()
        self.pipe = pipe
        self.stop_reading = False

    def process_line(self, line):
        # print("line:", line)
        if line.startswith("ModLoad: "):
            # stuff a load module event into the queue
            elems = re.split(r'\s+', line, 3)
            base = parse_addr(elems[1])
            end = parse_addr(elems[2])
            self.queue.put(LoadModuleEvent(elems[3].strip(), base))
        elif "offset expression evaluation failed" in line:
            self.queue.put(InternalErrorEvent(line))
        elif line.startswith("WaitForEvent failed, Win32 error "):
            self.queue.put(InternalErrorEvent(line))

    def run(self):
        # print 'ReaderThread.run()'
        curline = bytes()
        # read from the pipe
        while not self.stop_reading:
            ch = self.pipe.stdout.read(1)
            # print 'ReaderThread.run(): read %s' % ch
            if not ch:
                # add a closed event to the queue
                self.queue.put(PipeClosedEvent())
                # print 'ReaderThread.run(): read nothing'
                break
            if PYTHON3:
                self.queue.put(OutputEvent(ch.decode("ISO-8859-1")))
            else:
                self.queue.put(OutputEvent(ch))
            curline += ch
            if b"debugee initialization failed" in curline.lower() or b"win32 error 0n216" in curline.lower():
                print("cdb.exe error: \r\n{}".format(curline))
                self.queue.put(PipeClosedEvent())
                break
            if ch == '\n':
                if PYTHON3:
                    self.process_line(curline.decode("ISO-8859-1"))
                else:
                    self.process_line(curline)
                curline = bytes()


class Registers(object):
    def __init__(self, dbg):
        self.dbg = dbg
        self._initialized = True

    def get(self, name):
        buf = self.dbg.execute('r @%s' % name)
        if buf.find('Bad register') != -1:
            raise AttributeError('Bad register %s' % name)
        # TODO: implement xmm regs
        m = re.match(r'(.+)=([0-9A-Fa-f]+)', buf)
        if not m:
            raise AttributeError('Bad register %s (unable to parse value)' % name)
        val = int(m.group(2), 16)
        # print "Registers.get(%s) => %x" % (name, val)
        return val

    def set(self, name, value):
        # TODO: implement xmm regs
        buf = self.dbg.execute('r @%s=0x%x' % (name, value))
        if buf.find('Bad register') != -1:
            raise AttributeError('Bad register %s' % name)
        if buf.find('Syntax error') != -1:
            raise AttributeError('Syntax error %s, %s' % (name, value))

    def all(self):
        """
        return a dict of registers and their current values.
        """
        temp_map = AttrDict()
        regs = self.dbg.execute("r")
        temp_all = re.findall(r'([A-Za-z0-9]+)\=([0-9A-Fa-f]+)', regs)
        for entry in temp_all:
            temp_map[entry[0]] = int(entry[1], 16)
        return temp_map

    def __getattr__(self, item):
        """only called if there *isn't* an attribute with this name"""
        if not self.__dict__.has_key(item):
            return self.get(item)
        raise AttributeError(item)

    def __setattr__(self, item, value):
        if not self.__dict__.has_key('_initialized'):
            return dict.__setattr__(self, item, value)
        elif self.__dict__.has_key(item):
            return dict.__setattr__(self, item, value)
        else:
            return self.set(item, value)

    def __getitem__(self, item):
        try:
            return self.get(item)
        except AttributeError:
            raise KeyError(item)

    def __setitem__(self, item, value):
        try:
            self.set(item, value)
        except AttributeError:
            raise KeyError(item)


class PyCdb(object):
    def __init__(self, cdb_path=None):
        self.pipe = None
        if cdb_path:
            self.cdb_path = cdb_path
        else:
            self.cdb_path = self._find_cdb_path()
        self.output_buf_max = OUTPUT_BUF_MAX
        self.initial_command = ''
        self.debug_children = False
        self.initial_breakpoint = True
        self.hide_debugger = False
        self.final_breakpoint = False
        self.break_on_load_modules = False
        self.pipe_closed = True
        self.qthread = None
        self.breakpoints = {}
        self.bit_width = 32
        self.first_prompt_read = False
        self.cdb_cmdline = []
        self.is_debuggable = True
        self.read_to_prompt_timeout = 30

    def _find_cdb_path(self, include_x86=True, include_x64=True):
        # build program files paths
        pg_paths = [os.environ["PROGRAMFILES"]]
        if "ProgramW6432" in os.environ:
            self.bit_width = 64
            pg_paths.append(os.environ["ProgramW6432"])
        if "ProgramFiles(x86)" in os.environ:
            pg_paths.append(os.environ["ProgramFiles(x86)"])
        # potential paths to the debugger in program files
        dbg_paths = []
        if include_x86:
            dbg_paths += [
                "Windows Kits\\10\\Debuggers\\x86",
                "Windows Kits\\8.1\\Debuggers\\x86",
                "Windows Kits\\8.0\\Debuggers\\x86",
                "Debugging Tools for Windows (x86)",
                "Debugging Tools for Windows",
            ]
        if include_x64:
            dbg_paths += [
                "Windows Kits\\10\\Debuggers\\x64",
                "Windows Kits\\8.1\\Debuggers\\x64",
                "Windows Kits\\8.0\\Debuggers\\x64",
                "Debugging Tools for Windows (x64)",
                "Debugging Tools for Windows",
            ]
        # search the paths
        for p in pg_paths:
            for d in dbg_paths:
                test_path = os.path.join(p, d, 'cdb.exe')
                if os.path.exists(test_path):
                    return test_path
        # couldn't locate, raise an exception
        raise PyCdbException('Could not locate the cdb executable!')

    def _create_pipe(self, cmdline):
        self.pipe = subprocess.Popen(cmdline,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                     creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        self.qthread = CdbReaderThread(self.pipe)
        self.qthread.start()
        self.pipe_closed = False

    def add_cmdline_option(self, option):
        if type(option) == list:
            self.cdb_cmdline.append(option)
        else:
            self.cdb_cmdline.append(shlex.split(option))

    def _run_cdb(self, arguments):
        cmdline = [self.cdb_path]

        self._do_hide_debugger()

        if len(self.cdb_cmdline) > 0:
            cmdline += self.cdb_cmdline
        if self.debug_children:
            cmdline.append('-o')
        if not self.initial_breakpoint:
            cmdline.append('-g')
        if not self.final_breakpoint:
            cmdline.append('-G')
        if self.break_on_load_modules:
            cmdline += ['-xe', 'ld']
        if self.initial_command and len(self.initial_command) > 0:
            cmdline += ['-c', self.initial_command]
        # print(" ".join(cmdline + arguments))
        self._create_pipe(cmdline + arguments)

    def _do_hide_debugger(self):
        """
        Modify startup options to hide the debugger (patch IsDebugPresent to
        always return 0).

        Note that there may be some unexpected breakpoints if self.debug_children
        is also set.
        """
        if not self.hide_debugger:
            return

        initial_commands = []
        if self.initial_command is not None and len(self.initial_command) > 0:
            initial_commands.append(self.initial_command)

        # patches kernelbase!IsDebuggerPresent to be
        #     xor eax,eax
        #     ret
        initial_commands.insert(0, "eb kernelbase!IsDebuggerPresent 31 c0 c3")

        if not self.initial_breakpoint:
            # we want to patch IsDebuggerPresent as soon as the process starts, so
            # we need the initial breakpoint
            self.initial_breakpoint = True
            initial_commands.append("g")

        self.initial_command = " ; ".join(initial_commands)

    def closed(self):
        """
        return True if the pipe is closed
        """
        return self.pipe_closed

    def read_to_prompt(self, timeout=None, keep_output=True, debug=False):
        """
        This is the main 'wait' function, it dequeues event objects from
        the cdb output queue and acts on them.
        The actual output buffer is returned.
        """
        buf = ''
        lastch = None

        end_time = None
        if timeout:
            end_time = time.time() + timeout
        else:
            timeout = self.read_to_prompt_timeout
            end_time = time.time() + timeout
        remaining_time = timeout

        while True:

            # lets check to see if we have timed out before we do anything
            #
            # the logic here is that queue.get() only times out on events placed
            # into the queue but NOT on whether or not a prompt has been read, which
            # is the job of THIS function. So, if we have been sitting in this while
            # loop reading OutputEvents continuously (debugging outputting lots of data)
            # we will spin forever w/o timing out. To fix, we just keep track of
            # when we started fix the queue_timeout appropriately as well as check it
            # to see if we are done each time through the loop

            if timeout:
                now = time.time()
                remaining_time = end_time - now
                if now > end_time:
                    # we've been in this loop for too long, timeout!
                    print("timing out in read_to_prompt before calling queue.get()!")
                    raise PyCdbTimeoutException()

            try:
                event = self.qthread.queue.get(True, remaining_time)
            except queue.Empty:
                self.is_debuggable = False
                if timeout:
                    # if the queue.get() times out, we definitely have a timeout
                    print("timing out in read_to_prompt from call to queue.get()!")
                    raise PyCdbTimeoutException()
                break

            # print "read_to_prompt: %s" % event
            if isinstance(event, OutputEvent):
                self.is_debuggable = True
                ch = event.output
                # read one character at a time until we see a '> '
                if debug:
                    print("read: %s" % ch)
                buf += ch

                if len(buf) >= self.output_buf_max:
                    buf = buf[self.output_buf_max / 2:]

                # look for prompt
                if lastch == '>' and ch == ' ' and self.qthread.queue.empty():
                    # For initial breakpoint since we cant insert our marker
                    # On this one
                    if not self.first_prompt_read:
                        self.first_prompt_read = True
                        break

                    if COMMAND_FINISHED_MARKER in buf:
                        # remove the marker and the next prompt
                        # this is ok since the marker is inserted via a newline
                        # and not a semicolon.
                        # buf = buf.replace("%s\n" % COMMAND_FINISHED_MARKER, "")
                        pat = '%s\\n.+' % COMMAND_FINISHED_MARKER
                        buf = re.sub(pat, '', buf, flags=re.MULTILINE)
                        break
                lastch = ch
            elif isinstance(event, InternalErrorEvent):
                # might be possible to flag this and read the rest of the output
                # up to a prompt, but its safest to bail out now
                raise PyCdbInternalErrorException(buf)
            elif isinstance(event, PipeClosedEvent):
                self.pipe_closed = True
                raise PyCdbPipeClosedException(buf)
            elif isinstance(event, LoadModuleEvent):
                # this is a bit tricky, if we ARE breaking on modload
                # then we don't want to call the handler as it will be
                # called when process_event is called. However, if
                # we ARE NOT breaking on modload, then we probably should
                # call here
                if not self.break_on_load_modules:
                    self.on_load_module(event)
        if DEBUG_INOUT:
            print("<< " + "\n<< ".join(buf.splitlines()))
        return buf if keep_output else ""

    def write_pipe(self, buf):
        if DEBUG_INOUT:
            print(">> " + buf)
        self.pipe.stdin.write('{}\r\n.echo {}\r\n'.format(buf, COMMAND_FINISHED_MARKER).encode("ISO-8859-1"))
        try:
            self.pipe.stdin.flush()
        except OSError:
            # handle occasional error `OSError: [Errno 22] Invalid argument`
            print("Ignoring OSError in flush() call")
            pass

    def continue_debugging(self):
        """
        tell cdb to go but don't issue a read to prompt
        """
        self.write_pipe('g')

    def on_load_module(self, event):
        pass

    def unhandled_breakpoint(self, bpnum):
        # no handler, just continue execution
        self.continue_debugging()

    def on_breakpoint(self, event):
        handled = False
        bpnum = event.bpnum
        # call the handler if there is one
        if bpnum in self.breakpoints:
            handler, address = self.breakpoints[bpnum]
            if handler:
                handler(event)
                # continue execution
                self.continue_debugging()
                handled = True
        if not handled:
            self.unhandled_breakpoint(bpnum)

    def on_exception(self, event):
        pass

    def spawn(self, arguments):
        self._run_cdb(arguments)

    def attach(self, pid):
        self._run_cdb(['-p', str(pid)])

    def _quit(self):
        try:
            self.write_pipe('q\r\n')
        except IOError as ioe:
            if ioe.errno != 22:  # ignore EINVAL
                raise ioe

    def quit(self):
        self._quit()
        self.qthread.stop_reading = True
        self.pipe.kill()
        self.is_debuggable = True

    def interrupt(self):
        self.pipe.send_signal(subprocess.signal.CTRL_BREAK_EVENT)

    def delayed_break(self, seconds):
        def do_break():
            time.sleep(seconds)
            self.interrupt()

        t = threading.Thread(target=do_break)
        t.setDaemon(True)
        t.daemon = True
        t.start()

    def execute(self, command):
        if not self.is_debuggable:
            raise Exception("PyCdb is not at a breakpoint. This is the only time "
                            "you may execute commands")

        self.write_pipe(command)
        # return the entire output except the prompt string
        output = self.read_to_prompt()
        return "\n".join(output.splitlines()[:-1]) + "\n"

    def evaluate(self, expression):
        output = self.execute("? " + expression)
        # take the last line of output as there can be annoying warnings interspersed
        # like: WARNING: Unable to verify checksum...
        # print "evaluate(" + expression + "): " + output
        lastline = output.splitlines()[-1]
        m = re.match(r'Evaluate expression: (\-?[0-9]+) = ([0-9A-Fa-f`]+)', lastline)
        if m:
            return parse_addr(m.group(2))
        else:
            return None

    def backtrace(self, frames=None):
        if frames is None:
            output = self.execute("k")
        else:
            output = self.execute("k %d" % frames)

        # Strip header line
        return "\n".join(output.split("\n")[1:])

    def cpp_object_type(self, ptr):
        if isinstance(ptr, str):
            ptr = int(ptr, 16)
        output = self.execute("ln poi(%x)" % ptr)
        matches = output.split("Exact matches:")
        if len(matches) != 2:
            return "Unknown Object"
        matches = matches[1].strip().split("\n")
        if len(matches) != 1:
            return "Unknown Object (multiple matches)"

        obj = matches[0].strip()
        if "vftable" not in obj:
            return "Object not recognizable vtable"

        return obj.split("::`vftable")[0]

    @property
    def cpu_type(self):
        buf = self.execute('.effmach')
        if buf.find('x86') != -1:
            return CPU_X86
        elif buf.find('x64') != -1:
            return CPU_X64
        else:
            raise PyCdbException('unknown architecture: %s' % buf.strip())

    @property
    def registers(self):
        return Registers(self)

    def set_register(self, register, value):
        self.execute("r @%s=%x" % (register, value))

    def read_mem(self, address, length):
        mem = ''
        rem = length
        if type(address) == int:
            address = addr_to_hex(address)
        output = self.execute('db %s L%X' % (address, length))
        for line in output.splitlines():
            chunk = 16
            if chunk > rem:
                chunk = rem
            elems = re.split(r'[\ -]+', line)[1:1 + chunk]
            for value in elems:
                if value == '??':
                    break
                mem += value.decode('hex')
            rem -= chunk
        return mem

    def read_u64(self, address):
        try:
            return struct.unpack('<Q', self.read_mem(address, 8))[0]
        except IndexError:
            return None

    def read_u32(self, address):
        try:
            return struct.unpack('<L', self.read_mem(address, 4))[0]
        except IndexError:
            return None

    def read_u16(self, address):
        try:
            return struct.unpack('<H', self.read_mem(address, 2))[0]
        except IndexError:
            return None

    def read_u8(self, address):
        try:
            return struct.unpack('<B', self.read_mem(address, 1))[0]
        except IndexError:
            return None

    def read_char(self, address):
        try:
            return self.read_mem(address, 1)
        except IndexError:
            return None

    def read_pointer(self, address):
        if self.cpu_type == CPU_X64:
            return self.read_u64(address)
        else:
            return self.read_u32(address)

    def write_mem(self, address, buf):
        if type(address) == int:
            address = addr_to_hex(address)
        temp_bytes = ''
        for b in buf:
            temp_bytes += b.encode('hex') + ' '
        return self.execute('eb %s %s' % (address, temp_bytes))

    def write_u64(self, address, val):
        return self.write_mem(address, struct.pack('<Q', val))

    def write_u32(self, address, val):
        return self.write_mem(address, struct.pack('<L', val))

    def write_u16(self, address, val):
        return self.write_mem(address, struct.pack('<H', val))

    def write_u8(self, address, val):
        return self.write_mem(address, struct.pack('<B', val))

    def search(self, value, mode="d", begin=0, end=0xFFFFFFFF):
        if self.bit_width == 64 and end == 0xFFFFFFFF:
            end = 0xFFFFFFFFFFFFFFFF

        if mode == "d" or mode == "w":
            return self.execute("s -%s %x L?%x %x" % (mode, begin, end, value))

        elif mode == "a" or mode == "b":
            return self.execute("s -%s %x L?%x %s" % (mode, begin, end, value))

        return ""

    def search_int(self, value, begin=0, end=0xFFFFFFFF):
        return self.search(value, "d", begin, end)

    def search_ascii(self, value, begin=0, end=0xFFFFFFFF):
        return self.search(value, "a", begin, end)

    def search_bytes(self, value, begin=0, end=0xFFFFFFFF):
        """ value should be a string "fe ed fa ce" """
        if isinstance(value, str):
            return self.search(value, "b", begin, end)

        print("Error: search_bytes called with non-string value.")
        return ""

    def modules(self):
        temp_map = {}
        output = self.execute('lmf')
        for line in output.splitlines()[1:]:
            elems = re.split(r'\s+', line, 3)
            if elems and len(elems) >= 4:
                base = parse_addr(elems[0])
                end = parse_addr(elems[1])
                temp_map[elems[2].lower()] = [base, end - base, elems[3].strip()]
        return temp_map

    def module_info_from_addr(self, address):
        mods = self.modules()
        for name in mods:
            modinfo = mods[name]
            base = modinfo[0]
            end = base + modinfo[1]
            if base <= address <= end:
                return self.module_info(name)
        return None

    def module_info(self, modname):
        buf = self.execute("lm vm %s" % modname)
        lines = buf.splitlines()
        if len(lines) < 2:
            return None
        modinfo = {}
        # parse the first line
        elems = re.split(r'\s+', lines[1], 3)
        modinfo['module_base'] = parse_addr(elems[0])
        modinfo['module_end'] = parse_addr(elems[1])
        modinfo['module_name'] = elems[2].strip()
        for line in lines[2:]:
            elems = line.split(':', 1)
            tok = elems[0].strip().replace(" ", "_").lower()
            val = elems[1].strip()
            modinfo[tok] = val
        return modinfo

    def _get_bp_nums(self):
        bpnums = []
        output = self.execute('bl')
        for line in output.splitlines():
            line = line.strip()
            elems = re.split(r'\s+', line)
            if len(elems) > 1 and len(elems[0]) > 0:
                bpnums.append(int(elems[0]))
        return bpnums

    def breakpoint(self, address, handler=None, bptype=BREAKPOINT_NORMAL, bpmode="e", condition=""):
        if type(address) == int:
            address = addr_to_hex(address)
        cmd = 'bp'
        if bptype == BREAKPOINT_UNRESOLVED:
            cmd = 'bu'
        elif bptype == BREAKPOINT_HARDWARE:
            cmd = 'ba %s 1' % bpmode
        elif bptype == BREAKPOINT_SYMBOLIC:
            # Try symbolic if bp fails
            cmd = 'bm'

        nums_before = self._get_bp_nums()
        if len(condition) > 0:
            if not (condition.startswith("j") or condition.startswith(".if")):
                # Add boiler plate
                condition = "j %s ''; 'gc' " % condition
            output = self.execute('%s %s "%s"' % (cmd, address, condition))

        else:
            output = self.execute('%s %s' % (cmd, address))

        nums_after = self._get_bp_nums()
        added_num = list(set(nums_after) - set(nums_before))
        if len(added_num) == 0:
            if cmd == 'bp':
                return self.breakpoint(address, handler, BREAKPOINT_SYMBOLIC, bpmode, condition)
            raise PyCdbException(output.strip())
        else:
            bpnum = added_num[0]
            self.breakpoints[bpnum] = [handler, address]
            return bpnum

    def breakpoint_disable(self, bpnum):
        self.execute("bd %u" % bpnum)

    def breakpoint_enable(self, bpnum):
        self.execute("be %u" % bpnum)

    def breakpoint_remove(self, bpnum):
        self.execute("bc %u" % bpnum)

    # convenience methods
    def bp(self, address, handler=None, condition=""):
        return self.breakpoint(address, handler, bptype=BREAKPOINT_NORMAL,
                               condition=condition)

    def bu(self, address, handler=None, condition=""):
        return self.breakpoint(address, handler, bptype=BREAKPOINT_UNRESOLVED,
                               condition=condition)

    # extract info about the breakpoint
    def breakpoint_info(self, bpnum):
        line = self.execute('bl %u' % bpnum)
        line = line.strip()
        elems = re.split(r'\s+', line)
        if len(elems) == 0 or len(elems[0]) == 0:
            return None
        num = int(elems[0])
        flags = elems[1]
        unresolved = 'u' in flags
        enabled = 'e' in flags
        if unresolved:
            addr = None
            name = elems[4]
            if name[0] == '(' and name[-1] == ')':
                name = name[1:-1]
        else:
            addr = parse_addr(elems[2])
            name = elems[6]
        return BreakpointInfo(num, name, flags, enabled, not unresolved, addr)

    def _exception_info(self):
        output = self.execute('.exr -1')
        if output.find('not an exception') != -1:
            return None

        address = 0
        code = 0
        desc = "Unknown"

        m = re.search(r'ExceptionAddress: ([0-9A-Fa-f`]+)', output)
        if m:
            address = parse_addr(m.group(1))

        m = re.search(r'ExceptionCode: ([0-9A-Fa-f]+) \(([^\)]+)\)', output)
        if m:
            code = parse_addr(m.group(1))
            desc = m.group(2)
        else:
            m = re.search(r'ExceptionCode: ([0-9A-Fa-f]+)', output)
            if m:
                code = parse_addr(m.group(1))

        ex = ExceptionEvent(address, code, desc)
        m = re.search(r'NumberParameters: ([0-9]+)', output)
        num_params = int(m.group(1))
        params = []
        for n in range(num_params):
            m = re.search(r'Parameter\[%u\]: ([0-9A-Fa-f`]+)' % n, output)
            if not m:
                return None
            params.append(parse_addr(m.group(1)))
        ex.params = params

        # try to read the text details line
        last_line = output.splitlines()[-1].strip()
        if not last_line.startswith("Parameter["):
            ex.details = last_line
            # try to parse the details line to extract the address that caused the exception
            m = re.search(r'address ([0-9A-Fa-f]+)', ex.details)
            if m:
                ex.fault_addr = parse_addr(m.group(1))

        return ex

    @staticmethod
    def _breakpoint_info(event_desc):
        m = re.search(r'Hit breakpoint ([0-9]+)', event_desc)
        if not m:
            return None
        bpnum = int(m.group(1))
        bp = BreakpointEvent(bpnum)
        # print "_breakpoint_info: %s" % bp
        return bp

    @staticmethod
    def _load_module_info(event_desc):
        m = re.search(r'Load module (.*) at ([0-9A-Fa-f`]+)', event_desc)
        if not m:
            return None
        module_path = m.group(1)
        module_base = parse_addr(m.group(2))
        lme = LoadModuleEvent(module_path, module_base)
        return lme

    @staticmethod
    def _exit_process_info(event_desc):
        m = re.search(r'Exit Process .*, code (\d+)', event_desc)
        if not m:
            return None
        exit_code = m.group(1)
        ep = ExitProcessEvent(exit_code)
        return ep

    def last_event(self):
        event = None
        output = self.execute('.lastevent')
        m = re.search(r'Last event: ([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\: (.*)$',
                      output, re.MULTILINE)
        if m:
            pid, tid, desc = m.groups()
            #
            # what type of event was this?
            #
            while True:  # always breaks at end
                # did the process exit?
                event = self._exit_process_info(desc)
                if event:
                    break
                # was this a breakpoint?
                event = self._breakpoint_info(desc)
                if event:
                    break
                # was this a load module event?
                event = self._load_module_info(desc)
                if event:
                    break
                # was it an exception?
                event = self._exception_info()
                # always break at the end
                break
            # if we have an event, set the base info
            if event:
                event.set_base(pid, tid, desc)
        return event

    def process_event(self):
        if not self.is_debuggable:
            return None
        event = self.last_event()
        if type(event) == BreakpointEvent:
            self.on_breakpoint(event)
        elif type(event) == LoadModuleEvent:
            self.on_load_module(event)
        elif type(event) == ExceptionEvent:
            self.on_exception(event)
        return event

    def shell(self, debug=False):
        print("Dropping to cdb shell.  'quit' to exit, 'pdb' for python debugger.")
        p = 'cdb> '
        last_input = ''
        while True:
            try:
                temp_input = input(p)
                input_st = temp_input.strip().lower()
                p = ''
                if input_st == 'quit':
                    break
                elif input_st == 'pdb':
                    import pdb
                    pdb.set_trace()
                    p = 'cdb> '
                else:
                    if len(input_st) == 0:
                        # nothing was entered, repeat last command like windbg
                        temp_input = last_input
                    self.write_pipe(temp_input)
                    output = self.read_to_prompt(debug=debug)
                    sys.stdout.write(output)
                    sys.stdout.flush()
                last_input = temp_input
            except EOFError:
                break
