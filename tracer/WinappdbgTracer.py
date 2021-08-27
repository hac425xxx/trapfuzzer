# -*- coding: UTF-8 -*-
from winappdbg import Debug, win32, HexDump
from winappdbg.win32 import *
from time import time
import winappdbg
from winappdbg.util import MemoryAddresses
import subprocess
from threading import Timer
import threading
import subprocess
from common import *
import os
import errno
import shutil
import socket
import sys
import struct
import time
import signal
import random
import json

import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class WinappdbgTracer:
    def __init__(self, args=[], bbfiles=[], output="", module_names=[], logger=None):
        self.cmdline = ' '.join(args)
        script_dir = os.path.dirname(os.path.realpath(__file__))

        self.verbose = False

        self.args = args

        self.workspace = output
        self.coverage_module_name = module_names

        self.basic_block_info = self.load_bb_file(bbfiles)

        self.coverage_module_full_path = ""

        self.current_origin_seed = ""
        self.current_input_file = ""
        self.exception_case_count = 0

        if not logger:
            self.logger = CustomLogger()
        else:
            self.logger = logger

    def load_bb_file(self, bbfiles=[]):
        bb_info = {}
        for bbfile in bbfiles:
            bb = {}
            bb['full_path'] = ""
            bb['image_base'] = 0
            bb['image_end'] = 0
            bb['bb-list'] = []

            fp = open(bbfile, "rb")

            file_rva_size = struct.unpack("<I", fp.read(4))[0]
            bb['rva_size'] = file_rva_size

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

            bb_info[fname] = bb
        return bb_info

    def patch_to_file(self, file_path, trace, info):
        fp = open(file_path, "r+b")
        for offset in trace:
            file_offset = info[offset]['faddr']
            origin_byte = info[offset]['origin_byte']
            fp.seek(file_offset)
            fp.write(origin_byte)
        fp.close()

        # import pdb
        # pdb.set_trace()
        self.logger.log("[trapfuzzer] patch {} bytes to {}!".format(
            len(trace), file_path))
    
    def quit(self):
        self.kill_process()

    def kill_process(self):
        pids = self.debugger.get_debugee_pids()
        # subprocess.call(["taskkill", "/f", "/im", "FoxitReader.exe"],
        #                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.call(["taskkill", "/f", "/im", "wpsphoto+.exe"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for pid in pids:
            try:
                proc = self.debugger.system.get_process(pid)
                proc.kill()
            except:
                pass
            subprocess.call(["taskkill", "/f", "/pid", str(pid)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.debugger.detach_from_all(True)

    def timeout_handler(self):
        self.kill_process()

    def handle_window_popup(self):
        return True
        
        import win32gui
        import win32api

        classname = "福昕阅读器"
        titlename = "#32770"
        hwnd = win32gui.FindWindow(classname, titlename)
        if hwnd != 0:
            self.kill_process()

    def exec_testcase(self, exit_basci_block=[], timeout=2):

        self.debugger = Debug(bKillOnExit=True)

        crash_info = ""
        exec_status = ExecStatus.NORMAL

        mainProc = self.debugger.execv(self.args, bFollow=False)

        timer = Timer(timeout, self.timeout_handler)
        timer.start()

        event = None
        endTime = time.time() + timeout
        while time.time() < endTime:
            if not mainProc.is_alive():
                break
            try:
                event = self.debugger.wait(1000)
            except WindowsError, e:
                if e.winerror in (win32.ERROR_SEM_TIMEOUT, win32.WAIT_TIMEOUT):
                    self.handle_window_popup()
                    continue
                raise

            if event.get_event_code() == win32.LOAD_DLL_DEBUG_EVENT:
                module = event.get_module()
                full_path = module.get_filename()
                mod_name = os.path.basename(full_path).lower()

                if self.basic_block_info.has_key(mod_name):
                    info = self.basic_block_info[mod_name]
                    if info['image_base'] == 0:
                        info['image_base'] = module.get_base()
                        info['image_end'] = module.get_base() + \
                            info['rva_size']
                        info['full_path'] = full_path
                        # print "[LOAD_DLL_DEBUG_EVENT] mod name:{}, full path:{}, base:0x{:X}".format(
                        #     mod_name, full_path, info['image_base'])

            elif event.get_event_code() == win32.CREATE_PROCESS_DEBUG_EVENT:
                full_path = event.get_filename()
                mod_name = os.path.basename(full_path).lower()
                if self.basic_block_info.has_key(mod_name):
                    info = self.basic_block_info[mod_name]
                    if info['image_base'] == 0:
                        info['image_base'] = event.raw.u.CreateProcessInfo.lpBaseOfImage
                        info['image_end'] = event.raw.u.CreateProcessInfo.lpBaseOfImage + \
                            info['rva_size']
                        info['full_path'] = full_path
                        # print "[CREATE_PROCESS_DEBUG_EVENT] mod name:{}, full path:{}, base:0x{:X}".format(
                        #     mod_name, full_path, info['image_base'])

            elif event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.get_exception_code() == win32.STATUS_BREAKPOINT:
                exit_process = False

                pc = event.get_thread().get_pc() - 1
                for k in self.basic_block_info.keys():
                    info = self.basic_block_info[k]
                    if pc >= info['image_base'] and pc <= info['image_end']:
                        rva = pc - info['image_base']

                        if rva in exit_basci_block:
                            # print "exec: {}!0x{:X}, exit!".format(k, rva)
                            exit_process = True
                            break

                        raw_bytes = info[rva]['origin_byte']
                        event.get_process().write(pc, raw_bytes)
                        event.get_thread().set_pc(pc)
                        endTime = time.time() + timeout
                        info['bb-list'].append(rva)

                        print "exec: {}!0x{:X}".format(k, rva)

                if exit_process:
                    break

            elif event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.get_exception_code() != win32.STATUS_BREAKPOINT and (event.is_last_chance() or event.get_exception_code() in [win32.STATUS_ACCESS_VIOLATION, win32.STATUS_ILLEGAL_INSTRUCTION, win32.STATUS_ARRAY_BOUNDS_EXCEEDED]):
                crash = winappdbg.Crash(event)
                full_rep = crash.fullReport()
                (exploitable, type, info) = crash.isExploitable()

                # print dir(event.get_thread())

                dis = ""
                # print help(event.get_process().read)
                code = ""
                try:
                    from capstone import *
                    code = event.get_process().read(crash.pc, 0x10)
                    # print code.encode("hex")
                    md = Cs(CS_ARCH_X86, CS_MODE_32)
                    for i in md.disasm(code, crash.pc):
                        dis = "0x{:x}:\t{}\t{}".format(
                            i.address, i.mnemonic, i.op_str)
                        break

                except Exception as e:
                    # print e
                    dis = "Could not disassemble"

                # print "found crash"
                # print full_rep
                # print dis

                exec_status = ExecStatus.CRASH
                crash_info += full_rep
                crash_info += "\n"
                crash_info += code.encode("hex")
                crash_info += "\n"
                crash_info += dis

                break

            try:
                self.debugger.dispatch()
            except:
                pass
            finally:
                self.debugger.cont()

        timer.cancel()
        self.kill_process()

        return (exec_status, crash_info)

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):

        exec_status, crash_info = self.exec_testcase(exit_basci_block, timeout)

        # if exec_status == ExecStatus.CRASH:
        #     # try again...
        #     exec_status, crash_info = self.exec_testcase(exit_basci_block, timeout)
        #     print crash_info

        trace_info = []
        for k in self.basic_block_info.keys():
            info = self.basic_block_info[k]
            t = TraceInfo(k, info['bb-list'])
            trace_info.append(t)

        ret = ExecResult(trace_info, exec_status, crash_info)

        if need_patch_to_file and ret.status == ExecStatus.NORMAL:
            for k in self.basic_block_info.keys():
                info = self.basic_block_info[k]
                if len(info['bb-list']) != 0:
                    count = 0
                    while count < 3:
                        try:
                            self.patch_to_file(
                                info['full_path'], info['bb-list'], info)
                            break
                        except:
                            self.kill_process()
                            count += 1
                            time.sleep(1)
                    
                    if count >= 3:
                        print("patch_to_file failed...")
                        exit(0)

        for k in self.basic_block_info.keys():
            info = self.basic_block_info[k]
            info['image_base'] = 0
            info['image_end'] = 0
            info['bb-list'] = []

        return ret


class WinappdbgRpcTracer:
    def __init__(self, pid=0, bbfiles=[], output="", module_names=[], logger=None):
        script_dir = os.path.dirname(os.path.realpath(__file__))

        self.verbose = False

        self.pid = pid

        self.workspace = output
        self.coverage_module_name = module_names

        self.basic_block_info = self.load_bb_file(bbfiles)

        self.coverage_module_full_path = ""

        self.current_origin_seed = ""
        self.current_input_file = ""
        self.exception_case_count = 0

        if not logger:
            self.logger = CustomLogger()
        else:
            self.logger = logger

        # Determine if we have 32 bit or 64 bit pointers.
        if win32.sizeof(win32.SIZE_T) == win32.sizeof(win32.DWORD):
            fmt = "%.8x    %.8x    %s"
            hdr = "%-8s    %-8s    %s"
        else:
            fmt = "%.16x    %.16x    %s"
            hdr = "%-16s    %-16s    %s"

        # Create a snapshot of the process, only take the heap list.
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)

        # Enumerate the modules.
        module = Module32First(hSnapshot)
        while module is not None:

            mod_name = os.path.basename(module.szExePath).lower()

            if self.basic_block_info.has_key(mod_name):
                self.basic_block_info[mod_name]['image_base'] = module.modBaseAddr
                self.basic_block_info[mod_name]['image_end'] = module.modBaseAddr + \
                    self.basic_block_info[mod_name]['rva_size']

                # Print the module address, size and pathname.
                print fmt % (module.modBaseAddr,
                             module.modBaseSize,
                             module.szExePath)

            # Next module in the process.
            module = Module32Next(hSnapshot)

        # No need to call CloseHandle, the handle is closed automatically when it goes out of scope.
        self.debugger = Debug()
        self.debugee_proc = self.debugger.attach(self.pid)
        self.is_set_breakpointed = False
        self.set_breakpoint_to_process(self.debugee_proc)

    def load_bb_file(self, bbfiles=[]):
        bb_info = {}
        for bbfile in bbfiles:
            bb = {}
            bb['full_path'] = ""
            bb['image_base'] = 0
            bb['image_end'] = 0
            bb['bb-list'] = []

            fp = open(bbfile, "rb")

            file_rva_size = struct.unpack("<I", fp.read(4))[0]
            bb['rva_size'] = file_rva_size

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

            bb_info[fname] = bb
        return bb_info

    def set_breakpoint_to_process(self, proc):
        for mod_name in self.basic_block_info:
            bb_info = self.basic_block_info[mod_name]
            for rva in bb_info.keys():
                if isinstance(rva, int):
                    bb = bb_info[rva]
                    proc.write(
                        bb_info['image_base'] + rva, '\xcc')

        print "set breakpoint to process!"

        self.is_set_breakpointed = True

    def patch_to_file(self, file_path, trace, info):
        fp = open(file_path, "r+b")
        for offset in trace:
            file_offset = info[offset]['faddr']
            origin_byte = info[offset]['origin_byte']
            fp.seek(file_offset)
            fp.write(origin_byte)
        fp.close()

        # import pdb
        # pdb.set_trace()
        self.logger.log("[trapfuzzer] patch {} bytes to {}!".format(
            len(trace), file_path))

    def kill_process(self):
        pids = self.debugger.get_debugee_pids()
        for pid in pids:
            try:
                proc = self.debugger.system.get_process(pid)
                proc.kill()
            except:
                pass
            subprocess.call(["taskkill", "/f", "/pid", str(pid)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.debugger.detach_from_all(True)

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=600.0):

        for i in exit_basci_block:
            for mod_name in self.basic_block_info.keys():
                bb_info = self.basic_block_info[mod_name]
                if bb_info.has_key(i):
                    self.debugee_proc.write(bb_info['image_base'] + i, '\xcc')
                    print "set breakpoint on 0x{:X} for exit bb!".format(i)

        crash_info = ""
        exec_status = ExecStatus.NORMAL

        mainProc = self.debugee_proc

        event = None
        endTime = time.time() + timeout
        while time.time() < endTime:
            if not mainProc.is_alive():
                break
            try:
                event = self.debugger.wait(1000)
            except WindowsError, e:
                if e.winerror in (win32.ERROR_SEM_TIMEOUT, win32.WAIT_TIMEOUT):
                    continue
                raise

            if event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.get_exception_code() == win32.STATUS_BREAKPOINT:
                exit_process = False

                pc = event.get_thread().get_pc() - 1
                for k in self.basic_block_info.keys():
                    info = self.basic_block_info[k]
                    if pc >= info['image_base'] and pc <= info['image_end']:
                        rva = pc - info['image_base']
                        raw_bytes = info[rva]['origin_byte']
                        event.get_process().write(pc, raw_bytes)
                        event.get_thread().set_pc(pc)
                        endTime = time.time() + timeout
                        info['bb-list'].append(rva)
                        print "exec: {}!0x{:X}".format(k, rva)

                        if rva in exit_basci_block:
                            exit_process = True
                            break

                if exit_process:
                    break

            elif event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.get_exception_code() != win32.STATUS_BREAKPOINT and (event.is_last_chance() or event.get_exception_code() in [win32.STATUS_ACCESS_VIOLATION, win32.STATUS_ILLEGAL_INSTRUCTION, win32.STATUS_ARRAY_BOUNDS_EXCEEDED]):
                crash = winappdbg.Crash(event)
                full_rep = crash.fullReport()
                (exploitable, type, info) = crash.isExploitable()
                try:
                    dis = event.get_thread().disassemble(
                        crash.pc, 0x10)[0][2]
                except:
                    dis = "Could not disassemble"

                print "found crash"
                print full_rep
                print dis

                exec_status = ExecStatus.CRASH
                crash_info += full_rep
                crash_info += "\n"
                crash_info += dis

                break

            try:
                self.debugger.dispatch()
            except:
                pass
            finally:
                self.debugger.cont()

        # print dir(self.debugger)

        trace_info = []
        for k in self.basic_block_info.keys():
            info = self.basic_block_info[k]
            t = TraceInfo(k, info['bb-list'])
            trace_info.append(t)

        ret = ExecResult(trace_info, exec_status, crash_info)

        for k in self.basic_block_info.keys():
            info = self.basic_block_info[k]
            # info['image_base'] = 0
            # info['image_end'] = 0
            info['bb-list'] = []

        return ret


if __name__ == "__main__":
    # tracer = WinappdbgTracer(
    #     ["C:\\Program Files\\Microsoft Office\\Root\\Office16\\WINWORD.EXE", "D:\\data\\input.doc"])
    # tracer.trace(timeout=8000)

    # tracer = WinappdbgTracer(
    #     ["C:\\Users\\XinSai\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.9828\\office6\\wps.exe", "C:\\input.doc"],
    #     ["C:\\data\\wps.exe-bb.txt"])

    # # 0x2c7fe
    # tracer.trace(timeout=8000, exit_basci_block=[0])

    # tracer = WinappdbgTracer(
    #     [
    #         "C:\\honyview\\HONEYVIEW-PORTABLE\\Honeyview32.exe",
    #         "C:\\honyview\\dbg\\dbg.gif"
    #     ],
    #     [
    #         "C:\\honyview\\bin\\honeyview32.exe-bb.txt"
    #     ])
    # tracer.trace(timeout=12, exit_basci_block=[0x213de])

    tracer = WinappdbgTracer(
        ["C:\\Program Files (x86)\\Foxit Software\\Foxit Reader\\FoxitReader.exe",
         "C:\\foxitpdf\\input.pdf"],
        ["C:\\foxitpdf\\foxitreader.exe-bb.txt"])
    tracer.trace(timeout=1200, exit_basci_block=[0x230B00B])

    # tracer = WinappdbgRpcTracer(
    #     5424,
    #     ["C:\\sgtool.exe-bb.txt"])

    # # 0x2c7fe

    # while True:
    #     tracer.trace(exit_basci_block=[0x212837, 0x208590], timeout=5)
    #     raw_input("xxxx")
