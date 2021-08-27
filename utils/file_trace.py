import gdb
import binascii


def hex_decode(hex_string):
    return binascii.a2b_hex(hex_string)


def hex_encode(raw):
    return binascii.b2a_hex(raw)


def parse_number(v):
    ret = string_to_number(v)
    return ret


def cached_lookup_type(_type):
    try:
        return gdb.lookup_type(_type).strip_typedefs()
    except RuntimeError:
        return None


def get_memory_alignment(in_bits=False):
    res = cached_lookup_type("size_t")
    if res is not None:
        return res.sizeof if not in_bits else res.sizeof * 8
    try:
        return gdb.parse_and_eval("$pc").type.sizeof
    except:
        pass
    raise EnvironmentError("GEF is running under an unsupported mode")


def string_to_number(s):
    ret = 0
    try:
        try:
            ret = long(s)
        except:
            ret = long(s, 16)
    except:
        try:
            ret = int(s)
        except:
            ret = int(s, 16)

    pointer_size = get_memory_alignment()
    if pointer_size == 4:
        ret = ret & 0xffffffff
    elif pointer_size == 8:
        ret = ret & 0xffffffffffffffff
    else:
        raise Exception(
            "string_to_number: Unknown pointer size: {}".format(pointer_size))
    return ret


def write_memory(addr, buf, size):
    inferior = gdb.selected_inferior()
    return inferior.write_memory(addr, buf, size)


def read_memory(addr, size):
    inferior = gdb.selected_inferior()
    mem = inferior.read_memory(addr, size)
    # print(type(mem))
    # print(dir(mem))
    ret = ""
    try:
        ret = mem.tobytes()
    except:
        ret = str(mem)
    return ret


def read_register(name):
    value = gdb.parse_and_eval("${}".format(name))
    ret = string_to_number(value)
    return ret


def get_backtrace():
    gdb.execute("bt 20")
    print("\n\n\n")


GOOD_FDS = []
GOOD_FPS = []


class AddFdBp(gdb.Breakpoint):
    def __init__(self, name):
        super(AddFdBp, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)

    def stop(self):
        global GOOD_FDS
        fd = read_register("rax")
        GOOD_FDS.append(fd)
        self.delete()
        print("[AddFdBp] current fds {}".format(GOOD_FDS))
        return False


class OpenGoodFile(gdb.Breakpoint):
    def __init__(self, name):
        super(OpenGoodFile, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)
        self.hitcount = 0

    def stop(self):
        rdi = read_register("rdi")
        fname = read_memory(rdi, 0x100)
        # print("open: {}".format(fname))
        fname = fname[:fname.find(b"\x00")]

        if b".doc" in fname or b".ppt" in fname:
            self.hitcount += 1
            if self.hitcount == 3:
                current_frame = gdb.selected_frame()
                caller = current_frame.older().pc()
                print("[OpenGoodFile] open {}, set bp on 0x{:x} to get fd\n".format(
                    fname, caller))
                get_backtrace()
                AddFdBp("*{}".format(caller))
            elif self.hitcount == 4:
                print("[OpenGoodFile] open {}, try to lock this".format(fname))
                current_frame = gdb.selected_frame()
                caller = current_frame.older().pc()
                AddFdBp("*{}".format(caller))
                get_backtrace()
            else:
                print("[OpenGoodFile] open {}, count: {}".format(
                    fname, self.hitcount))
        return False


class ReadGoodFd(gdb.Breakpoint):
    def __init__(self, name):
        super(ReadGoodFd, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)

    def stop(self):
        global GOOD_FDS
        rdi = read_register("rdi")
        if rdi in GOOD_FDS:
            print("[ReadGoodFd] read fd: {}".format(rdi))
            get_backtrace()
        return False


class CloseGoodFd(gdb.Breakpoint):
    def __init__(self, name):
        super(CloseGoodFd, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)

    def stop(self):
        global GOOD_FDS
        rdi = read_register("rdi")
        if rdi in GOOD_FDS:
            print("[CloseGoodFd] close fd: {}".format(rdi))
            get_backtrace()
            GOOD_FDS.remove(rdi)
        return False


class AddFpBp(gdb.Breakpoint):
    def __init__(self, name):
        super(AddFpBp, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)

    def stop(self):
        global GOOD_FPS
        fp = read_register("rax")
        GOOD_FPS.append(fp)
        self.delete()
        print("[AddFpBp] current fp {}".format(
            ["0x{:x}".format(x) for x in GOOD_FPS]))
        return False


class FopenGoodFile(gdb.Breakpoint):
    def __init__(self, name):
        super(FopenGoodFile, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)
        self.hitcount = 0

    def stop(self):
        rdi = read_register("rdi")
        fname = read_memory(rdi, 0x100)
        # print("open: {}".format(fname))
        fname = fname[:fname.find(b"\x00")]

        if b".doc" in fname:
            current_frame = gdb.selected_frame()
            caller = current_frame.older().pc()
            print("[FopenGoodFile] open {}, set bp on 0x{:x} to get fp\n".format(
                fname, caller))
            get_backtrace()
            AddFpBp("*{}".format(caller))
        return False


class FreadGoodFp(gdb.Breakpoint):
    def __init__(self, name):
        super(FreadGoodFp, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)

    def stop(self):
        global GOOD_FPS
        fp = read_register("rcx")
        if fp in GOOD_FPS:
            print("[FreadGoodFp] fread fp: {}".format(fp))
            get_backtrace()
        return False


class FcloseGoodFp(gdb.Breakpoint):
    def __init__(self, name):
        super(FcloseGoodFp, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)

    def stop(self):
        global GOOD_FPS
        rdi = read_register("rdi")
        if rdi in GOOD_FPS:
            print("[FcloseGoodFp] fclose fp: {}".format(rdi))
            get_backtrace()
            GOOD_FPS.remove(rdi)
        return False


gdb.execute("set confirm off")
gdb.execute("set history save on")
gdb.execute("set pagination off")
gdb.execute("set verbose off")
gdb.execute("handle SIGALRM print nopass")
try:
    gdb.execute("set disable-randomization on")
    # this will raise a gdb.error unless we're on x86
    gdb.execute("set disassembly-flavor intel")
except gdb.error:
    # we can safely ignore this
    pass


OpenGoodFile("*open")
ReadGoodFd("*read")
CloseGoodFd("*close")


FopenGoodFile("*fopen")
FreadGoodFp("*fread")
FcloseGoodFp("*fclose")
