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


class DynamorioTracer:
    def __init__(self, args=[], drrun_path="", client_path="", output="", module_names=[], exit_basci_block=[]):
        script_dir = os.path.dirname(os.path.realpath(__file__))

        self.workspace = os.path.abspath(output)
        self.cov_module_name_list = module_names
        self.debug = False
        self.exit_basci_block = exit_basci_block

        self.trace_output_path = os.path.join(self.workspace, "dy.trace")

        command_list = []

        command_list.append(drrun_path)
        command_list.append("-c")
        command_list.append(client_path)

        command_list.append("-debug")

        for n in self.cov_module_name_list:
            command_list.append("-coverage_module")
            command_list.append(n)

        command_list.append("-trae_output")
        command_list.append(self.trace_output_path)
        command_list.append("--")

        for i in args:
            command_list.append(i)

        self.command_list = command_list

    def timeout_handler(self):
        try:
            print "timeout"
            self.is_timeout = True
            self.process.kill()
        except Exception as e:
            print(e)

    def quit(self):
        self.process.kill()

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):
        self.is_timeout = False

        # print " ".join(self.command_list)
        process_stdout = open("stdout.txt", "w")
        self.process = subprocess.Popen(" ".join(self.command_list), shell=True, cwd=self.workspace, stdin=subprocess.PIPE,
                                        stdout=process_stdout.fileno(), stderr=subprocess.STDOUT)

        timer = Timer(timeout, self.timeout_handler)

        try:
            timer.start()
            self.process.communicate()
        finally:
            timer.cancel()

        status = ""

        with open(os.path.join(self.workspace, "dy.status"), "r") as fp:
            status = fp.readline().strip()

        # print(status)
        crash_info = ""
        s = ExecStatus.NORMAL
        if status == "crash":
            s = ExecStatus.CRASH
            with open(os.path.join(self.workspace, "dy.crash"), "r") as fp:
                crash_info = fp.read()
        if self.is_timeout:
            s = ExecStatus.DOS

        cov_trace_info = {}

        trace_info = []

        with open(self.trace_output_path, "rb") as fp:
            while True:
                try:
                    mod_id = struct.unpack("<I", fp.read(4))[0]
                    rva = struct.unpack("<I", fp.read(4))[0]
                except:
                    break

                mod_name = self.cov_module_name_list[mod_id]
                if not cov_trace_info.has_key(mod_name):
                    cov_trace_info[mod_name] = []

                cov_trace_info[mod_name].append(rva)

        for k in cov_trace_info.keys():
            t = TraceInfo(k, cov_trace_info[k])
            trace_info.append(t)
        ret = ExecResult(trace_info, s, crash_info)
        return ret


# ~/DynamoRIO-Linux-7.91.18355/bin64/drrun -c libbincov.so -debug  -coverage_module test -trae_output bb.bin  -xx  -- ./test


if __name__ == "__main__":
    tracer = DynamorioTracer(["/home/hac425/code/example/test", "/home/hac425/code/in/1"],
                             "/home/hac425/DynamoRIO-Linux-7.91.18355/bin64/drrun", "/home/hac425/code/tracer/dy_bin_cov/build/libbincov.so", "/home/hac425/code/output/", ["test"])
    print tracer.trace()
