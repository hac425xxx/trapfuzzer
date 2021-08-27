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


class WinappdbgCSTracer:
    def __init__(self, args=[], bbfiles=[], output="", module_names=[], logger=None):
        self.cmdline = ' '.join(args)
        self.script_dir = os.path.dirname(os.path.realpath(__file__))

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

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('127.0.0.1', 21212))
        self.server_sock.listen(1)

        self.start_agent_process()

    def start_agent_process(self):

        python_path = "C:\\Python27_32\\python.exe"
        agent_script_path = os.path.join(self.script_dir, "WinappdbgAgent.py")
        config_file_path = os.path.join(self.workspace, "config.json")

        command = "{} {} {}".format(python_path, agent_script_path, config_file_path)
        # print command
        self.agent_process = subprocess.Popen(command, shell=True)

        try:
            self.client_sock, _ = self.server_sock.accept()
        except Exception as e:
            print e
            exit(1)

        cmd = struct.unpack("<I", self.client_sock.recv(4))[0]

        if cmd != AGENT_HELLO_CMD:
            print "recv invaild cmd: 0x{:x}".format(cmd)
            exit(1)

        self.client_sock.sendall(struct.pack("<I", GET_AGENT_PID))
        self.agent_pid = struct.unpack("<I", self.client_sock.recv(4))[0]

    def kill_process(self, pid):
        subprocess.call(["taskkill", "/f", "/pid", str(pid)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def kill_agent_process(self):
        self.kill_process(self.agent_pid)
        self.agent_process.kill()

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
        self.kill_agent_process()

    def process_running(self, processName):
        #Iterate over the all the running process
        for proc in psutil.process_iter():
            try:
                # Check if process name contains the given name string.
                if processName.lower() in proc.name().lower():
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return False

    def exec_testcase(self, timeout):
        data = struct.pack("<I", RUN_TESTCASE)
        data += struct.pack("<I", timeout)
        self.client_sock.sendall(data)

        ret_code = struct.unpack("<I", self.client_sock.recv(4))[0]

        if ret_code == RESTART_AGENT or self.process_running("POWERPNT.EXE"):
            self.kill_agent_process()
            self.start_agent_process()
            return None

        if ret_code == WRITE_TRACE_RESULT:
            data_len = struct.unpack("<I", self.client_sock.recv(4))[0]
            data = self.client_sock.recv(data_len)

            # print data
            ret = ExecResult()
            try:
                ret.load_json(data)
            except Exception as e:
                print e
                print "data length: {}, recv length: {}".format(data_len, len(data))
                print data
                exit(1)
            return ret

        print "unknown ret_code 0x{:x}".format(ret_code)

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):
        ret = None
        while not ret:
            ret = self.exec_testcase(timeout)
        return ret


if __name__ == "__main__":
    tracer = WinappdbgCSTracer(
        [
            "C:\\Program Files (x86)\\WPSPhoto+\\wpsphoto+.exe",
            "C:\\input.jpg"
        ],
        [
            "C:\\wpsphoto\\patch\\photo.dll-bb.txt"
        ]
    )
    tracer.trace(need_patch_to_file=True,
                 exit_basci_block=[0x515EE], timeout=2000)
