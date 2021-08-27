from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.process_event import ProcessExit
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from ptrace.debugger.memory_mapping import readProcessMappings
from signal import SIGTRAP, SIGINT, SIGSEGV, SIGABRT
import os
from common import *
import logging
import struct
import shutil

class PythonPtraceTracer():
    def __init__(self, args=[], bbfile="", module_name=""):
        self.bbinfo = self.load_bb_file(bbfile)
        self.dbg = PtraceDebugger()
        self.target_args = args
        self.coverage_module_name = module_name

    def quit(self):
        pass

    def create_and_attach_process(self, args):
        env = None
        args[0] = locateProgram(args[0])
        pid = createChild(args, True, env)
        return self.dbg.addProcess(pid, True)

    def load_bb_file(self, bbfile):
        bb = {}
        fp = open(bbfile, "rb")
        fname_sz = struct.unpack("<I", fp.read(4))[0]
        fname = fp.read(fname_sz).strip("\x00")
        
        while True:
            data = fp.read(12)
            if len(data) < 12:
                break
            voff, foff, instr_sz = struct.unpack("<III", data)
            instr = fp.read(instr_sz)
            bb[voff] = {}
            bb[voff]['faddr'] = foff
            bb[voff]['origin_byte'] = instr
        fp.close()

        bb_info = {}
        bb_info[fname] = bb
        return bb_info

    def read_map(self, pid):
        f = open("/proc/{}/maps".format(pid), "r")
        data = f.read()
        f.close()
        return data

    def clean_screen(self):
        # os.system("clear")
        pass

    def patch_to_file(self, trace, info):
        fp = open(info['full_path'], "r+b")
        for offset in trace:
            file_offset = info[offset]['faddr']
            origin_byte = info[offset]['origin_byte']
            fp.seek(offset)
            fp.write(origin_byte)
        fp.close()

        print("[trapfuzzer] patch {} bytes to {}!".format(len(trace), info['full_path']))

    def parse_pclist(self, map_mem, pc_list):
        base_dict = {}
        ret = []
        for pc in pc_list:
            for m in map_mem:
                if m.pathname not in base_dict:
                    base_dict[m.pathname] = m.start

                if pc >= m.start and pc <= m.end:
                    base = base_dict[m.pathname] 

                    s = "{}!0x{:X}".format(os.path.basename(m.pathname), pc - base)
                    print(s)
                    ret.append(s)

        return ret

    def get_crash_info(self, process):
        map_mem = readProcessMappings(process)
        backtrace = process.getBacktrace()
        # ip = process.getInstrPointer()

        iplist = []

        for b in backtrace:
            iplist.append(b.ip)

        ret = self.parse_pclist(map_mem, iplist)
        # import ipdb
        # ipdb.set_trace()

        return '\n'.join(ret)


    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):
        module_name = self.coverage_module_name
        info = self.bbinfo[module_name]
        process = self.create_and_attach_process(self.target_args)

        status = ExecStatus.NORMAL
        crash_info = ""



        bb_trace = []
        while True:
            process.cont()
            try:
                signal = process.waitSignals()
            except ProcessExit:
                if verbose:
                    print("[trapfuzzer] Catch ProcessExit!")
                break

            if signal.signum == SIGTRAP:
                map_mem = readProcessMappings(process)
                for fname in self.bbinfo:
                    for m in map_mem:
                        if m.pathname and fname in m.pathname:
                            info['image_base'] = m.start
                            info['full_path'] = m.pathname
                            break

                ip = process.getInstrPointer()
                trap_addr = ip - 1



                offset = trap_addr - info['image_base']
                obyte = info[offset]['origin_byte']

                if verbose:
                    print(
                        "[trapfuzzer] Catch SIGTRAP on 0x{:X}".format(offset))

                if offset in exit_basci_block:
                    process.terminate()
                    print("[trapfuzzer] enter exit block pointer")
                    break

                process.writeBytes(trap_addr, obyte)
                process.setInstrPointer(trap_addr)
                bb_trace.append(offset)
            elif signal.signum == SIGSEGV:
                crash_info = self.get_crash_info(process)
                process.terminate()
                self.clean_screen()
                logging.critical("[trapfuzzer] Catch SIGSEGV")
                status = ExecStatus.CRASH
                break
            elif signal.signum == SIGABRT:
                crash_info = self.get_crash_info(process)

                process.terminate()
                self.clean_screen()
                logging.critical("[trapfuzzer] Catch SIGABRT")
                status = ExecStatus.ABORT
                break
            else:
                logging.critical("[trapfuzzer] Catch Signals: {}".format(signal))

        ret = ExecResult(module_name, list(set(bb_trace)), status, crash_info)

        if need_patch_to_file and status == ExecStatus.NORMAL and len(bb_trace) > 0:
            self.patch_to_file(ret.trace, info)

        self.dbg.quit()
        self.dbg.deleteProcess(process)
        del process
        return ret

if __name__ == '__main__':
    tracer = PythonPtraceTracer(["/opt/kingsoft/wps-office/office6/wps", "/home/hac425/input.doc"], "/home/hac425/wps_fuzzing/bb.txt", "libkso.so")
    tracer.trace(verbose=True)