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


class GdbTracer:
    def __init__(self, args=[], bbfiles=[], output="", module_names=[], logger=None):
        self.cmdline = ' '.join(args)
        script_dir = os.path.dirname(os.path.realpath(__file__))
        shutil.copyfile("{}/cmd.gdb".format(script_dir),
                        "{}/cmd.gdb".format(output))
        shutil.copyfile("{}/trap.py".format(script_dir),
                        "{}/trap.py".format(output))

        for bbfile in bbfiles:
            shutil.copyfile(bbfile, "{}/{}".format(output, os.path.basename(bbfile)))

        self.workspace = output
        self.coverage_module_name = module_names

        self.basic_block_info = self.load_bb_file(bbfiles)

        self.coverage_module_full_path = ""

        self.sever_thead = threading.Thread(target=self.communicate_server_func)
        self.server_running = False
        self.sever_thead.setDaemon(True)
        self.sever_thead.start()

        while not self.server_running:
            time.sleep(0.1)

        self.current_origin_seed = ""
        self.current_input_file = ""
        self.exception_case_count = 0

        if not logger:
            self.logger = CustomLogger()
        else:
            self.logger = logger

        self.debug = False

    def communicate_server_func(self):
        port = random.randint(20000, 50000)

        module_info_list = []
        for n in self.basic_block_info.keys():
            module_info_list.append((n, self.basic_block_info[n]['rva_size']))

        config = {}
        with open("{}/config.json".format(self.workspace), "r") as fp:
            config = json.loads(fp.read())
        config['fuzzer-gdb-port'] = "{}".format(port)

        config['module_info_list'] = module_info_list

        with open("{}/config.json".format(self.workspace), "w") as fp:
            fp.write(json.dumps(config))

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('127.0.0.1', port))
        self.server_sock.listen(1)

        self.server_running = True

        while True:
            self.client_sock = None
            try:
                self.client_sock, _ = self.server_sock.accept()
            except:
                break

            try:
                data = self.client_sock.recv(2)
                if data == "ok":
                    self.client_sock.sendall("next")

                while True:
                    mod_idx = self.client_sock.recv(1)
                    data = self.client_sock.recv(4)
                    if len(data) == 0:
                        break
                    # print("gdb.trace: {}, len: {}".format(data, len(data)))

                    mod_idx = struct.unpack("<b", mod_idx)[0]

                    mod_name = module_info_list[mod_idx][0]  # get module name

                    # print "module name:{}".format(mod_name) 

                    info = self.basic_block_info[mod_name]

                    offset = struct.unpack("<I", data)[0]

                    # print("offset:0x{:08X}".format(offset))

                    raw_byte = info[offset]['origin_byte']
                    self.client_sock.sendall(raw_byte)

            except Exception as e:
                print e
                self.logger.log("gdb.trace: {}".format(e))
            finally:
                self.client_sock.close()

        self.server_running = False

    def quit(self):
        self.server_sock.close()

    def load_bb_file(self, bbfiles=[]):
        bb_info = {}
        for bbfile in bbfiles:
            bb = {}
            bb['full_path'] = ""
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
        self.logger.log("[trapfuzzer] patch {} bytes to {}!".format(len(trace), file_path))

    def timeout_handler(self):
        target_pid = None
        self.is_timeout = True
        with open("{}/target.pid".format(self.workspace), "r") as fp:
            target_pid = int(fp.read().strip())
        os.kill(target_pid, signal.SIGINT)

    def exec_with_gdb(self, timeout=30):

        command = "/usr/bin/gdb -q -x {}/cmd.gdb  --args {}".format(self.workspace, self.cmdline)

        self.is_timeout = False
        self.p = subprocess.Popen(command, shell=True, cwd=self.workspace, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        ret = True

        output = ""
        if self.debug:
            log_file = open("debug.log", "w")

        timer = Timer(timeout, self.timeout_handler)
        try:
            timer.start()
            # stdout, stderr = p.communicate()
            space_count = 0
            while True:
                l = self.p.stdout.readline()
                output += l
                if self.debug:
                    print(l)
                    log_file.write(l + "\n")
                if "received signal SIGTRAP" in l:
                    space_count = 0
                    self.p.stdin.write("c\n")
                elif l.strip() == "":
                    space_count += 1
                    if space_count == 20:
                        break
                elif "[trapfuzzer] save_bb_trace" in l:
                    break
        except Exception as e:
            res = self.p.stdout.read()
            if "[trapfuzzer] save_bb_trace" not in res:
                dst_file_path = "{}/tracer-exception-{}.bin".format(self.workspace, self.exception_case_count)
                log_path = "{}/tracer-exception-{}.log".format(self.workspace, self.exception_case_count)
                shutil.copyfile(self.current_input_file, dst_file_path)

                with open(log_path, "w") as fp:
                    fp.write(output + res)

                self.exception_case_count += 1
                self.logger.log("GdbTracer.trace: {}, exception file: {}, from: {}".format(e, self.current_origin_seed,
                                                                                           dst_file_path))
                ret = False

                # timer.cancel() # for debug
                # import ipdb
                # ipdb.set_trace()
        finally:
            timer.cancel()

        self.p.kill()
        self.p.wait()
        if self.debug:
            log_file.close()

        return ret

    def get_crash_hash(self, data):
        crash_hash = ""
        for l in data.split("\n"):
            # print l
            addr = re.findall("#\d+\s+(.*?)\s+in", l)
            if len(addr) >= 1:
                crash_hash += addr[0][-3:]
                # print crash_hash

        return crash_hash

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):

        try_count = 0
        while try_count < 3:
            if self.exec_with_gdb(timeout):
                break

        status = ""
        with open("{}/gdb.status".format(self.workspace), "r") as fp:
            status = fp.readline().strip()

        # print(status)
        crash_info = ""
        s = ExecStatus.NORMAL
        if status == "crash":
            s = ExecStatus.CRASH
            with open("{}/gdb.crash".format(self.workspace), "r") as fp:
                crash_info = fp.read()

            with open(os.path.join(self.workspace, "stacktrace.txt"), "r") as fp:
                crash_hash = self.get_crash_hash(fp.read())
                crash_info += "\ncrash-hash: {} ".format(crash_hash)

        if self.is_timeout:
            s = ExecStatus.DOS

        trace_info = []

        with open("{}/gdb.trace".format(self.workspace), "r") as fp:
            module_trace_list = json.loads(fp.read())
            for mt in module_trace_list:
                t = TraceInfo(mt['module_name'], mt['bbl-list'])
                trace_info.append(t)

        # print(bbs)
        # print(module_name)
        ret = ExecResult(trace_info, s, crash_info)
        if need_patch_to_file and ret.status == ExecStatus.NORMAL:
            for mt in module_trace_list:
                if len(mt['bbl-list']) != 0:
                    self.patch_to_file(mt['full_path'], mt['bbl-list'], self.basic_block_info[mt['module_name']])
        return ret


class GdbRunTracer:
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

        with open("{}/cmd.gdb".format(output), "w") as fp:
            fp.write(self.generate_gdb_cmd_file())

        for bbfile in bbfiles:
            shutil.copyfile(bbfile, "{}/{}".format(output, os.path.basename(bbfile)))

        config = {}
        with open(os.path.join(self.workspace, "config.json"), "r") as fp:
            config = json.loads(fp.read())

        trapfuzzer_gdb_path = ""
        if config.has_key("tracer-binary"):
            trapfuzzer_gdb_path = config['tracer-binary']

        if not os.path.exists(trapfuzzer_gdb_path):
            print "trapfuzzer gdb path ({}) don't exit!".format(trapfuzzer_gdb_path)
            exit(0)

        command = "{} -q -x {}/cmd.gdb  --args {}".format(trapfuzzer_gdb_path, self.workspace, self.cmdline)

        self.client_sock = None

        self.output = output

        port = 12241
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('127.0.0.1', port))
        self.server_sock.listen(1)

        process_stdout = open("stdout.txt", "w")

        self.process = subprocess.Popen(command, shell=True, cwd=self.workspace, stdin=subprocess.PIPE,
                                        stdout=process_stdout.fileno(), stderr=subprocess.STDOUT)

        self.client_sock, _ = self.server_sock.accept()

    def generate_gdb_cmd_file(self):
        data = ""
        data += "set confirm off\n"
        data += "set pagination off\n"
        # data += "set auto-solib-add off\n"



        exit_bb_list = ",".join(["0x{:x}".format(x) for x in self.exit_basci_block])
        data += "set-exit-bb-list {}\n".format(exit_bb_list)

        for bbfile in self.bbfiles:
            data += "load-trapfuzzer-info {}\n".format(bbfile)

        if self.patch_to_binary:
            data += "set-fuzz-config fuzzmode,patch_to_binary\n"
        else:
            data += "set-fuzz-config fuzzmode\n"

        data += "run\n"
        return data

    def timeout_handler(self):
        try:
            self.is_timeout = True
            target_pid = None
            with open("{}/target.pid".format(self.workspace), "r") as fp:
                target_pid = int(fp.read().strip())
            os.kill(target_pid, signal.SIGINT)
            # print("notify {}".format(target_pid))
        except Exception as e:
            print(e)

    def quit(self):
        self.client_sock.close()
        self.server_sock.close()
        self.process.kill()

    def get_crash_hash(self, data):
        crash_hash = ""
        for l in data.split("\n"):
            # print l
            addr = re.findall("#\d+\s+(.*?)\s+in", l)
            if len(addr) >= 1:
                crash_hash += addr[0][-3:]
                # print crash_hash

        return crash_hash

    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=60.0):
        self.is_timeout = False
        timer = Timer(timeout, self.timeout_handler)

        try:
            timer.start()
            data = struct.unpack("<I", self.client_sock.recv(4))[0]
            # print("recv: 0x{:X}".format(data))
            self.client_sock.sendall(struct.pack("<I", 0xdd11))

            # while True:
            #     l = self.process.stdout.readline()
            #     print l,

            data = struct.unpack("<I", self.client_sock.recv(4))[0]
            # print("recv: 0x{:X}".format(data))
        finally:
            timer.cancel()

        status = ""
        with open("{}/gdb.status".format(self.workspace), "r") as fp:
            status = fp.readline().strip()

        # print(status)
        crash_info = ""
        s = ExecStatus.NORMAL
        if status == "crash":
            s = ExecStatus.CRASH
            with open("{}/gdb.crash".format(self.workspace), "r") as fp:
                crash_info = fp.read()

            with open(os.path.join(self.workspace, "stacktrace.txt"), "r") as fp:
                crash_hash = self.get_crash_hash(fp.read())
                crash_info += "\ncrash-hash: {} ".format(crash_hash)

        if self.is_timeout:
            s = ExecStatus.DOS

        trace_info = []
        for cov_mod_name in self.coverage_module_name:
            data = ""
            trace_fpath = os.path.join(self.output, "{}.trace".format(cov_mod_name))
            with open(trace_fpath, "r") as fp:
                data = fp.read().strip()
                bbl_list = []
                for b in data.split(","):
                    if b.strip():
                        bbl_list.append(int(b, 16))

                t = TraceInfo(cov_mod_name, bbl_list)
                trace_info.append(t)
        ret = ExecResult(trace_info, s, crash_info)
        return ret


if __name__ == "__main__":
    # tracer = GdbTracer(["/home/hac425/code/example/test", "/home/hac425/code/in/1"],
    #                       ["/home/hac425/code/example/test-bb.txt"], "/home/hac425/code/output/", ["test"])
    # print tracer.trace()

    tracer = GdbRunTracer(["/home/hac425/code/example/test", "/home/hac425/code/in/1"],
                          ["/home/hac425/code/example/test-bb.txt"], "/home/hac425/code/output/", ["test"])
    print tracer.trace()
