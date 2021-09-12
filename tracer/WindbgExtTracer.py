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


class WindbgExtTracer:
    debug_mode = False

    def __init__(self, args=[], bbfiles=[], output="", module_names=[], patch_to_binary=False, exit_basci_block=[]):
        self.cmdline = ' '.join(args)
        script_dir = os.path.dirname(os.path.realpath(__file__))

        self.workspace = os.path.abspath(output)
        self.coverage_module_name = module_names
        self.coverage_module_full_path = ""
        self.debug = False
        self.patch_to_binary = patch_to_binary
        self.exit_basci_block = exit_basci_block
        self.bbfiles = bbfiles

        for bbfile in bbfiles:
            shutil.copyfile(bbfile, os.path.join(output, os.path.basename(bbfile)))

        config = {}
        with open(os.path.join(self.workspace, "config.json"), "r") as fp:
            config = json.loads(fp.read())

        command = "C:\\windbg-sdk-samples\\Debug\\healer.exe"

        if config.has_key("tracer-binary"):
            command = config['tracer-binary']

        if not os.path.exists(command):
            print "{} not exists!".format(command)
            exit(1)

        self.client_sock = None

        self.output = output

        port = random.randint(20000, 50000)
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('127.0.0.1', port))
        self.server_sock.listen(1)


        config['server_sock_port'] = port
        config['is_fuzz_mode'] = 1
        with open(os.path.join(self.workspace, "config.json"), "w") as fp:
            fp.write(json.dumps(config))

        if not self.debug_mode:
            process_stdout = open(os.path.join(self.workspace, "stdout.txt"), "w")
            stdout = process_stdout.fileno()
            self.process = subprocess.Popen([command, os.path.join(self.workspace, "config.json")], shell=True, cwd=self.workspace, stdout=stdout)
        else:
            self.process = subprocess.Popen([command, os.path.join(self.workspace, "config.json")], shell=True, cwd=self.workspace, stdout=stdout)

        self.client_sock, _ = self.server_sock.accept()

    def timeout_handler(self):
        print "timeout_handler"
        try:
            self.is_timeout = True

            subprocess.call(["taskkill", "/f", "/im", "wpp.exe"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            subprocess.call(["taskkill", "/f", "/im", "wps.exe"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            subprocess.call(["taskkill", "/f", "/im", "et.exe"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        except Exception as e:
            print(e)

    def quit(self):
        self.client_sock.close()
        self.server_sock.close()
        self.process.kill()

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2):
        self.is_timeout = False
        timer = Timer(timeout, self.timeout_handler)

        try:
            data = struct.unpack("<I", self.client_sock.recv(4))[0]
            if self.debug_mode:
                print("task-start flag: 0x{:X}".format(data))

            self.client_sock.sendall(struct.pack("<I", 0xdd11))

            timer.start()

            data = struct.unpack("<I", self.client_sock.recv(4))[0]

            if self.debug_mode:
                print("task-end flag: 0x{:X}".format(data))
        
        except KeyboardInterrupt as e:
            raise e
        finally:
            timer.cancel()

        status = ""
        with open(os.path.join(self.workspace, "tracer.status"), "r") as fp:
            status = fp.readline().strip()

        crash_info = ""
        s = ExecStatus.NORMAL
        if status == "crash":
            s = ExecStatus.CRASH
            with open(os.path.join(self.workspace, "crashinfo.txt"), "r") as fp:
                crash_info = fp.read()

            with open(os.path.join(self.workspace, "stacktrace.txt"), "r") as fp:

                backtrace = ""
                crash_hash = ""
                for l in fp:
                    crash_hash += l.strip()[-3:]
                    backtrace += l

                crash_hash = crash_hash[:18]

                crash_info += "\n\nbacktrace\n\n"
                crash_info += backtrace
                crash_info += "\n\n"
                crash_info += "crash-hash: {} ".format(crash_hash)

        if self.is_timeout:
            s = ExecStatus.DOS

        trace_info = []
        for cov_mod_name in self.coverage_module_name:
            trace_fpath = os.path.join(self.output, "{}.trace".format(cov_mod_name))
            with open(trace_fpath, "r") as fp:
                bbl_list = []
                for b in fp:
                    if b.strip():
                        bbl_list.append(int(b, 16))

                t = TraceInfo(cov_mod_name, bbl_list)
                trace_info.append(t)

        ret = ExecResult(trace_info, s, crash_info)

        return ret


if __name__ == "__main__":
    tracer = WindbgExtTracer(["C:\\Program Files (x86)\\Foxit Software\\Foxit Reader\\FoxitReader.exe"],
                             ["C:\\Program Files (x86)\\Foxit Software\\Foxit Reader\\FoxitReader.exe-bb.txt"],
                             "C:\\output\\", ["FoxitReader.exe"])
    print tracer.trace()
