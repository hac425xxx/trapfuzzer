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
import psutil

import sys

reload(sys)
sys.setdefaultencoding('utf-8')


class WinappdbgAgent:
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

        self.connect_server()

        self.check_start = False
        self.cpu_monitor_thread = threading.Thread(target=self.proc_cpu_monitor_func)
        self.cpu_monitor_thread.start()

    def connect_server(self):
        self.tracer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tracer_sock.connect(("127.0.0.1", 21212))
        self.tracer_sock.sendall(struct.pack("<I", AGENT_HELLO_CMD))
        cmd = struct.unpack("<I", self.tracer_sock.recv(4))[0]

        if cmd != GET_AGENT_PID:
            print "connect_server failed, cmd: 0x{:x}".format(cmd)
            exit(1)

        self.tracer_sock.sendall(struct.pack("<I", os.getpid()))


    def get_cpu_usage_by_pid(self, pid):
        p = psutil.Process(pid)
        return p.cpu_percent(1)

    def get_cpu_usage_by_pid_no(self, pid):
        p = psutil.Process(pid)
        p.cpu_percent(None)
        time.sleep(0.5)
        usage = p.cpu_percent(None)
        return usage

    def kill_when_cpu_free(self, pid):
        """
        当cpu使用率为0时 kill 进程
        :param proc:
        :return:
        """

        self.is_exec_timeout = False

        count = 0
        while count < 2:
            
            if not self.check_start:
                return

            usage = self.get_cpu_usage_by_pid_no(pid)
            # print usage
            if usage == 0:
                count += 1
        
        print "kill process by cpu moitor"
        self.kill_process()

    def proc_cpu_monitor_func(self):
        while True:
            while not self.check_start:
                time.sleep(0.1)

            try:
                pids = self.debugger.get_debugee_pids()
                for pid in pids:
                    self.kill_when_cpu_free(pid)
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                print e
                
                


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
            fname = fp.read(fname_sz).strip("\x00").lower()

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

    def kill_process(self, kill_twice=True):
        pids = self.debugger.get_debugee_pids()
        # self.debugger.detach_from_all(True)

        # subprocess.call(["taskkill", "/f", "/im", "FoxitReader.exe"],
        #                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.call(["taskkill", "/f", "/im", "POWERPNT.EXE"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.debugger.detach_from_all(True)

        if kill_twice:
            for pid in pids:
                try:
                    proc = self.debugger.system.get_process(pid)
                    proc.kill()
                except:
                    pass
                subprocess.call(["taskkill", "/f", "/pid", str(pid)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def timeout_handler(self):
        self.is_exec_timeout = True
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

    def exec_testcase(self, exit_basci_block=[], timeout=2, need_patch_to_file=False):

        self.is_exec_timeout = False
        self.debugger = Debug(bKillOnExit=True)

        crash_info = ""
        exec_status = ExecStatus.NORMAL

        mainProc = self.debugger.execv(self.args, bFollow=False)

        self.check_start = True

        timer = Timer(timeout * 3, self.timeout_handler)
        timer.start()

        event = None
        endTime = time.time() + timeout
        while time.time() < endTime:
            if not mainProc.is_alive():
                break
            try:
                event = self.debugger.wait(1000)
            except KeyboardInterrupt:
                self.kill_process()
                exit(0)
            except WindowsError, e:
                if e.winerror in (win32.ERROR_SEM_TIMEOUT, win32.WAIT_TIMEOUT):
                    # self.handle_window_popup()
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
                            print "exec: {}!0x{:X}, exit!".format(k, rva)
                            exit_process = True
                            break

                        raw_bytes = info[rva]['origin_byte']
                        event.get_process().write(pc, raw_bytes)
                        event.get_thread().set_pc(pc)
                        endTime = time.time() + timeout
                        info['bb-list'].append(rva)

                        # print "exec: {}!0x{:X}".format(k, rva)

                if exit_process:
                    self.kill_process(kill_twice=False)
                    break

            elif event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.get_exception_code() != win32.STATUS_BREAKPOINT and (
                    event.is_last_chance() or event.get_exception_code() in [win32.STATUS_ACCESS_VIOLATION,
                                                                             win32.STATUS_ILLEGAL_INSTRUCTION,
                                                                             win32.STATUS_ARRAY_BOUNDS_EXCEEDED]):


                crash = winappdbg.Crash(event)
                full_rep = crash.fullReport()
                (exploitable, type, info) = crash.isExploitable()

                dis = ""
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
                    dis = "Could not disassemble"
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

        if time.time() >= endTime:
            self.is_exec_timeout = True

        if self.is_exec_timeout:
            exec_status = ExecStatus.DOS
            c = 10
            if len(info['bb-list']) < c:
                c = len(info['bb-list'])
            for i in range(c):
                print "{}".format(info['bb-list'][-(c - i)])

        timer.cancel()

        self.check_start = False

        self.kill_process()

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
                        except Exception as e:
                            print e
                            self.kill_process()
                            count += 1
                            time.sleep(1)

                    if count >= 3:
                        print("patch {} failed!".format(info['full_path']))
                        return (0, ret)

        for k in self.basic_block_info.keys():
            info = self.basic_block_info[k]
            info['image_base'] = 0
            info['image_end'] = 0
            info['bb-list'] = []

        return (1, ret)

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[]):

        while True:
            cmd, timeout = struct.unpack("<II", self.tracer_sock.recv(8))
            if cmd == RUN_TESTCASE:
                ret_code, exec_result_info = self.exec_testcase(
                    exit_basci_block, timeout, need_patch_to_file)
                if ret_code:
                    data = ""
                    data += struct.pack("<I", WRITE_TRACE_RESULT)

                    if need_patch_to_file:
                        for ti in exec_result_info.trace:
                            if len(ti.bb_list) > 20:
                                ti.bb_list = ti.bb_list[:10]

                    ret_data = exec_result_info.to_json()
                    data += struct.pack("<I", len(ret_data))
                    data += ret_data

                    # print ret_data

                    self.tracer_sock.sendall(data)
                else:
                    data = ""
                    data += struct.pack("<I", RESTART_AGENT)
                    self.tracer_sock.sendall(data)

            else:
                print "invaild cmd: 0x{:x}".format(cmd)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "WinappdbgCSTracer.py config.json"
        exit(1)

    config = {}

    with open(sys.argv[1], "r") as fp:
        config = json.loads(fp.read())

    exit_bb_list = []

    for bb in config['exit_basci_block_list'].split(","):
        exit_bb_list.append(int(bb, 16))

    tracer = WinappdbgAgent(
        args=config['args'],
        bbfiles=config['basic_block_file_path'],
        module_names=config['coverage_module_name'],
        output=config['output']
    )

    tracer.trace(need_patch_to_file=config['patch_to_binary'], exit_basci_block=exit_bb_list)
