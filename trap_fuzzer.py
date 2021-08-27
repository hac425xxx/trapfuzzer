# /usr/bin/env python
# -*- coding: UTF-8 -*-

from sys import stderr, argv, exit
import os
import ctypes
from ctypes import *
import random
import hashlib
import logging
import shutil
from tracer.common import *
from tracer.gdbtracer import GdbTracer
from tracer.gdbtracer import GdbRunTracer
import json
import platform

import sys
import time
import socket
import threading
import datetime
from mutator.radamsa import RadamsaMutator
from mutator.custom import VanapaganMutator
from mutator.honggfuzz import HonggfuzzMutater

try:
    from database.seed import SeedDB
except:
    pass


# import pydevd_pycharm
# pydevd_pycharm.settrace('192.168.245.1', port=12341, stdoutToServer=True, stderrToServer=True)

class Fuzzer:
    def __init__(self, config_filename):

        self.config_filename = config_filename

        self.total_module_trace_info = {}

        self.testcase_list = []
        self.crash_list = []
        self.dos_list = []

        self.avg_run_time = 60
        self.timeout_ratio = 5

        self.fuzzer_status = "running"
        self.exec_stage = ""

        self.cur_mutator = None

        self.exit_basci_block = []
        self.current_file = ""

        random.seed(int(time.time()))

        self.logger = CustomLogger()

        self.config = None
        with open(self.config_filename, "r") as fp:
            self.config = json.loads(fp.read())
        self.output = os.path.abspath(self.config['output'])

        if not self.config.has_key("resume_execution"):
            self.resume_fuzzing = False
        else:
            self.resume_fuzzing = self.config['resume_execution']

        if not self.config.has_key("patch_to_binary"):
            self.patch_to_binary = False
        else:
            self.patch_to_binary = self.config['patch_to_binary']

        self.cov_module_name = self.config['coverage_module_name']
        self.input_path_read_by_target = self.config['file_read_by_target']
        self.manage_port = int(self.config['manage_port'])

        self.trace_mode = self.config["tracer"]

        # import ipdb
        # ipdb.set_trace()

        if self.config.has_key("db_host"):
            self.enable_database = True
        else:
            self.enable_database = False

        if self.enable_database:

            db_host = self.config['db_host']
            db_user = self.config['db_user']
            db_passwd = self.config['db_passwd']
            db_database = self.config['db_database']
            db_table = self.config['db_table']
            self.db = SeedDB(db_host, db_user, db_passwd, db_database, db_table)

            if not self.config.has_key("file_type"):
                self.file_type = os.path.basename(self.input_path_read_by_target)

                if len(self.file_type.split('.')) > 2:
                    self.file_type = self.file_type.split('.')[-1]

            else:
                self.file_type = self.config["file_type"]

        self.loaded_testcase_list = {}
        self.loaded_testcase_file = os.path.join(self.output, "loaded-testcase.txt")

        if not self.resume_fuzzing:
            if os.path.exists(self.output):
                raise Exception("{} is exits!".format(self.output))
                shutil.rmtree(self.output)
            os.mkdir(self.output)

        shutil.copyfile(self.config_filename, os.path.join(self.output, "config.json"))

        if platform.system() == "Linux":
            import signal
            signal.signal(signal.SIGINT, self.exit_handler)

        mutator_name = self.config['mutator']

        self.min_testcase_size = 0
        self.exec_timeout = 50

        if self.config.has_key('min_testcase_size'):
            self.min_testcase_size = self.config['min_testcase_size']

        if self.config.has_key('exec_timeout'):
            self.exec_timeout = self.config['exec_timeout']

        if self.config.has_key('timeout_ratio'):
            self.timeout_ratio = self.config['timeout_ratio']

        self.mutator_list = []
        if mutator_name == "Vanapagan-mutator":
            self.mutator_list.append(VanapaganMutator())
        elif mutator_name == "radamsa-mutator":
            self.mutator_list.append(RadamsaMutator())
        elif mutator_name == "honggfuzz-mutator":
            self.mutator_list.append(HonggfuzzMutater())
        elif mutator_name == "all":
            self.mutator_list.append(VanapaganMutator())
            self.mutator_list.append(RadamsaMutator())
            self.mutator_list.append(HonggfuzzMutater())
        else:
            self.logger.log("unknown mutator: {}".format(mutator_name))
            exit(1)

        self.total_exec_count = 0
        self.exec_speed = 0
        self.total_exec_time = 0

        self.last_new_path_found = ""
        self.last_crash_found = ""
        self.last_dos_found = ""

        self.import_case_dir = ""

        self.sever_thead = threading.Thread(target=self.manage_thead)
        self.server_running = False
        self.sever_thead.setDaemon(True)
        self.sever_thead.start()

        while not self.server_running:
            time.sleep(0.1)

        for bb in self.config['exit_basci_block_list'].split(","):
            if bb.strip() == "":
                continue
            self.exit_basci_block.append(int(bb.strip(), 16))

        if self.trace_mode == "gdb":
            self.tracer = GdbTracer(
                self.config['args'], self.config['basic_block_file_path'], self.output, self.cov_module_name,
                self.logger)
        elif self.trace_mode == "gdb-run":
            self.tracer = GdbRunTracer(
                self.config['args'], self.config['basic_block_file_path'], self.output, self.cov_module_name,
                self.patch_to_binary, self.exit_basci_block)
        elif self.trace_mode == "python-ptrace":
            from tracer.PythonPtraceTracer import PythonPtraceTracer
            self.tracer = PythonPtraceTracer(
                self.config['args'], self.config['basic_block_file_path'], self.cov_module_name)
        elif self.trace_mode == "DynamorioTracer":
            from tracer.DynamorioTracer import DynamorioTracer
            self.tracer = DynamorioTracer(
                self.config['args'], self.config['drrun_path'], self.config['instrument_path'], self.output,
                self.cov_module_name, self.exit_basci_block)
        elif self.trace_mode == "WinappdbgTracer":
            from tracer.WinappdbgTracer import WinappdbgTracer
            self.tracer = WinappdbgTracer(
                self.config['args'], self.config['basic_block_file_path'], self.output, self.cov_module_name,
                self.logger)
        elif self.trace_mode == "WinappdbgCSTracer":
            from tracer.WinappdbgCSTracer import WinappdbgCSTracer
            self.tracer = WinappdbgCSTracer(
                self.config['args'], self.config['basic_block_file_path'], self.output, self.cov_module_name,
                self.logger)
        elif self.trace_mode == "windbg-ext-tracer":
            from tracer.WindbgExtTracer import WindbgExtTracer
            self.tracer = WindbgExtTracer(
                self.config['args'], self.config['basic_block_file_path'], self.output, self.cov_module_name,
                self.logger)
        else:
            raise Exception("unknown tracer {}".format(self.trace_mode))

        if self.resume_fuzzing:
            self.load_prev_output()

    def convert_time_to_str(self, t):
        if (t < 10):
            t = '0' + str(t)
        else:
            t = str(t)
        return t

    def sec_to_data(self, y):

        d = int(y // 86400)

        h = int((y // 3600) % 24)
        m = int((y % 3600) // 60)
        s = int(y % 60)

        h = self.convert_time_to_str(h)
        m = self.convert_time_to_str(m)
        s = self.convert_time_to_str(s)
        d = self.convert_time_to_str(d)

        ret = "{} days {}h {}m {}s".format(d, h, m, s)

        return ret

    def handle_client_request(self, sock):
        cmd_help = ['status (s)', 'seed_info (si)', 'set_seed_exec_count (sc)', 'enable_debug (eb)',
                    'disable_debug (db)'
                    'stop', 'testcase (t)', 'crash (c)', 'timeout_ratio (tr)', 'import_case dir', 'quit (q)']
        help_info = "\n".join(cmd_help) + "\n"
        while True:
            cmd = sock.recv(100).strip()
            cmd_list = cmd.split(" ")
            data = ""
            try:
                if cmd_list[0] in ["s", "status"]:
                    data = "\nstatus\n"
                    data += "stage: {}\n".format(self.exec_stage)
                    data += "total dos:      {}\n".format(len(self.dos_list))
                    data += "total crash:    {}\n".format(len(self.crash_list))
                    data += "total new path: {}\n".format(len(self.testcase_list))

                    data += "speed: {}/min\n".format(self.exec_speed * 60)
                    data += "trace mode: {}\n".format(self.trace_mode)

                    data += "stage exec count:{}\n".format(self.total_exec_count)

                    bb_count = 0
                    for k in self.total_module_trace_info.keys():
                        bb_count += len(self.total_module_trace_info[k])
                    data += "total bb count:  {}\n".format(bb_count)

                    data += "total exec time: {}\n".format(self.sec_to_data(self.total_exec_time))

                    data += "coverage module: {}\n".format(','.join(self.cov_module_name))

                    data += "config mutator:  {}\n".format(self.config['mutator'])
                    m = self.cur_mutator
                    if m:
                        data += "current mutator: {}\n".format(m.__mutator_name__)

                    if self.last_dos_found != "":
                        data += "last dos: {}\n".format(self.last_dos_found)

                    if self.last_crash_found != "":
                        data += "last crash:  {}\n".format(self.last_crash_found)

                    if self.last_new_path_found != "":
                        data += "last new path:  {}\n".format(self.last_new_path_found)

                    data += "current time:  {}\n".format(self.logger.get_current_time())
                    data += "avg_run_time:  {}s, timeout ratio: {}\n".format(self.avg_run_time, self.timeout_ratio)
                    data += "output: {}\n".format(self.output)
                    data += "current seed file: {}\n".format(self.current_file)

                elif cmd_list[0] in ["seed_info", "si"]:
                    data = "Queue INFO\n"
                    for seed in self.testcase_list:
                        data += "{}\n".format(seed)

                elif cmd_list[0] in ["set_seed_exec_count", "sc"]:
                    if len(cmd_list) != 3:
                        data = "set_seed_exec_count idx exec_count\n"
                    else:
                        seed = self.testcase_list[int(cmd_list[1])]
                        seed.exec_count = int(cmd_list[2])
                elif cmd_list[0] in ["enable_debug", "eb"]:
                    self.tracer.debug = True
                elif cmd_list[0] in ["disable_debug", "db"]:
                    self.tracer.debug = False
                elif cmd_list[0] in ["testcase", "t"]:
                    if len(cmd_list) != 2:
                        data = "testcase idx\n"
                    else:
                        seed = self.testcase_list[int(cmd_list[1])]
                        data = "path:{}/trapfuzz-testcase-{}.bin\n".format(
                            self.output, seed.idx)
                        data += "trace\n"

                        trace_string = ""
                        for ti in seed.trace:
                            trace_string += "{}\n".format(ti.module_name)
                            trace_string += ','.join(['{:X}'.format(x) for x in ti.bb_list])
                            trace_string += '\n'

                        data += trace_string
                        data += "\n"


                elif cmd_list[0] in ["crash", "c"]:
                    if len(cmd_list) != 2:
                        data = "crash idx\n"
                    else:
                        crash = self.crash_list[int(cmd_list[1])]
                        data = "path:{}/trapfuzz-crash-{}.bin\n".format(
                            self.output, crash.idx)
                        data += "crash infomation\n{}\n\n".format(
                            crash.crash_info)
                        data += "crash hash: {}".format(crash.trace_hash)
                elif cmd_list[0] in ["timeout_ratio", "tr"]:
                    if len(cmd_list) != 2:
                        data = "tr 10\n"
                    else:
                        self.timeout_ratio = int(cmd_list[1])
                        data = "set timeout_ratio to {}\n".format(
                            self.timeout_ratio)
                elif cmd_list[0] in ["stop"]:
                    self.fuzzer_status = "stop"
                elif cmd_list[0] in ["h", "help"]:
                    data = help_info
                elif cmd_list[0] in ["import_case"]:
                    if len(cmd_list) != 2:
                        data = "import_case dir!"
                    else:
                        if not os.path.exists(cmd_list[1]):
                            data = "{} don't exists!".format(cmd_list[1])
                        else:
                            self.set_fuzz_stage("loading-testcase")
                            self.import_case_dir = cmd_list[1]

                elif cmd_list[0] in ["q", "quit"]:
                    sock.sendall("quit\n")
                    break
                else:
                    data = "Invaild cmd: {}\n".format(cmd)
                    data += help_info
                    data += "\n\n"
            except Exception as e:
                data = "command error: {}, data:{}\n".format(e, cmd)

            data += "\n"
            sock.sendall(data)

    def manage_thead(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('0.0.0.0', self.manage_port))
        self.server_sock.listen(1)
        self.server_running = True
        while True:
            self.client_sock = None
            if not self.server_running:
                break
            try:
                self.client_sock, _ = self.server_sock.accept()
            except:
                break

            try:
                self.handle_client_request(self.client_sock)
            except Exception as e:
                print(e)
            finally:
                self.client_sock.close()

        self.server_running = True

    def load_prev_output(self):

        with open(self.loaded_testcase_file, "r") as fp:
            for l in fp:
                fname = l.strip()
                self.loaded_testcase_list[fname] = 1

        self.load_fuzz_stage()

        idx = 0
        while True:
            case_path = os.path.join(
                self.output, "trapfuzz-testcase-{}.bin".format(idx))
            trace_path = os.path.join(
                self.output, "trapfuzz-testcase-{}.trace".format(idx))

            if not os.path.isfile(case_path):
                break

            trace_info = []
            with open(trace_path, "r") as fp:
                while True:
                    try:
                        bb_list = []
                        module_name = fp.readline().strip()
                        data = fp.readline().strip()

                        if not data:
                            break

                        if not self.patch_to_binary:
                            for bb in data.strip().split(","):
                                if bb != "":
                                    bb_list.append(int(bb, 16))

                        trace_info.append(TraceInfo(module_name, bb_list))
                    except:
                        break

            for ti in trace_info:
                if not self.total_module_trace_info.has_key(ti.module_name):
                    if self.patch_to_binary:
                        self.total_module_trace_info[ti.module_name] = set()
                    else:
                        self.total_module_trace_info[ti.module_name] = set(ti.bb_list)
                else:
                    if not self.patch_to_binary:
                        module_total_bbs = self.total_module_trace_info[ti.module_name]
                        new_bbs = module_total_bbs | set(ti.bb_list)
                        unique_bb_count = len(new_bbs) - len(module_total_bbs)
                        if unique_bb_count:
                            self.total_module_trace_info[ti.module_name] = new_bbs

            testcase = Testcase(idx, trace_info)
            self.testcase_list.append(testcase)

            if self.enable_database:
                hash = self.calc_file_md5(case_path)
                seed = self.db.get_seed(hash)
                testcase.seed_hash = hash
                if not seed:
                    fsize = os.path.getsize(case_path)
                    file_name = os.path.basename(case_path)
                    self.db.insert_new_seed("", hash, fsize, file_type=self.file_type, file_name=file_name)
            idx += 1

        idx = 0
        while True:
            case_path = os.path.join(
                self.output, "trapfuzz-crash-{}.bin".format(idx))
            trace_path = os.path.join(
                self.output, "trapfuzz-crash-{}.trace".format(idx))

            if not os.path.isfile(case_path):
                break

            data = ""
            with open(trace_path, "r") as fp:
                data = fp.read()

            crash = Crash(idx, [], data)
            self.crash_list.append(crash)

            if self.enable_database:
                hash = self.calc_file_md5(case_path)
                seed = self.db.get_seed(hash)
                if not seed:
                    fsize = os.path.getsize(case_path)
                    file_name = os.path.basename(case_path)
                    self.db.insert_new_seed("", hash, fsize, file_type="{}-crash".format(self.file_type),
                                            file_name=file_name,
                                            extra_info=crash.crash_info)

            idx += 1

        idx = 0
        while True:
            case_path = os.path.join(
                self.output, "trapfuzz-dos-{}.bin".format(idx))
            trace_path = os.path.join(
                self.output, "trapfuzz-dos-{}.trace".format(idx))

            if not os.path.isfile(case_path):
                break

            trace_info = []
            with open(trace_path, "r") as fp:
                bb_list = []
                module_name = fp.readline().strip()
                data = fp.readline().strip()

                try:
                    for bb in data.strip().split(","):
                        if bb != "":
                            bb_list.append(int(bb, 16))
                except:
                    pass

                trace_info.append(TraceInfo(module_name, bb_list))

            dos = Dos(idx, trace_info)
            self.dos_list.append(dos)

            if self.enable_database:
                hash = self.calc_file_md5(case_path)
                seed = self.db.get_seed(hash)
                if not seed:
                    fsize = os.path.getsize(case_path)
                    file_name = os.path.basename(case_path)
                    self.db.insert_new_seed("", hash, fsize, file_type="{}-dos".format(self.file_type),
                                            file_name=file_name)

            idx += 1

        self.logger.log("[trapfuzzer] load tesecase:{}, crash:{}, dos:{}".format(
            len(self.testcase_list), len(self.crash_list), len(self.dos_list)))

        if self.exec_stage == "loading-testcase":
            self.load_testcase(self.config['testcase'])

    def exit_handler(self, sig, frame):
        self.server_sock.close()
        self.tracer.quit()
        self.logger.log('Exit Trapfuzzer!')
        sys.exit(0)

    def has_new_path(self, trace):
        has_new_path = False
        for ti in trace:
            if not self.total_module_trace_info.has_key(ti.module_name):

                if self.patch_to_binary:
                    if len(ti.bb_list) > 0:
                        has_new_path = True
                else:
                    self.total_module_trace_info[ti.module_name] = set(ti.bb_list)
                    has_new_path = True
            else:
                if self.patch_to_binary:
                    if len(ti.bb_list) > 0:
                        has_new_path = True
                else:
                    module_total_bbs = self.total_module_trace_info[ti.module_name]
                    new_bbs = module_total_bbs | set(ti.bb_list)
                    unique_bb_count = len(new_bbs) - len(module_total_bbs)
                    if unique_bb_count:
                        self.total_module_trace_info[ti.module_name] = new_bbs
                        has_new_path = True
        return has_new_path

    def is_unique_crash(self, crash):
        for c in self.crash_list:
            if c.trace_hash == crash.trace_hash:
                return False
        return True

    def is_unique_dos(self, dos):
        for c in self.dos_list:
            if c.trace_hash == dos.trace_hash:
                return False
        return True

    def save_case_to_file(self, type, idx, trace, extrainfo=""):
        shutil.copyfile(self.input_path_read_by_target,
                        "{}/trapfuzz-{}-{}.bin".format(self.output, type, idx))
        with open("{}/trapfuzz-{}-{}.trace".format(self.output, type, idx), "wb") as fp:
            if extrainfo:
                fp.write('\n[extra infomation]\n')
                fp.write(extrainfo)
                fp.write("\n")

            fp.write('\n[trace infomation]\n')

            data = ""
            for ti in trace:
                data += "{}\n".format(ti.module_name)
                data += ','.join(['0x{:X}'.format(x) for x in ti.bb_list])
                data += '\n'
            fp.write(data)

    def save_crash(self, trace, crash_info=""):
        crash_idx = len(self.crash_list)
        crash = Crash(crash_idx, trace, crash_info)
        if not self.is_unique_crash(crash):
            return False

        self.save_case_to_file("crash", crash_idx, trace, crash_info)
        self.crash_list.append(crash)

        return True

    def save_dos(self, trace, exec_time=-1):
        idx = len(self.dos_list)
        dos = Dos(idx, trace, exec_time)

        if self.patch_to_binary or self.is_unique_dos(dos):
            self.save_case_to_file("dos", idx, trace, "exec-time: {}".format(exec_time))
            self.dos_list.append(dos)
            return True
        else:
            return False

    def find_max_trace_case(self):
        max_trace_count = 0
        max_testcase = None
        for c in self.testcase_list:
            trace_count = c.get_trace_count()
            if trace_count > max_trace_count:
                max_trace_count = trace_count
                max_testcase = c
        return max_testcase

    def remove_dup_case(self, case):
        dup_list = []

        for c in self.testcase_list:
            if c == case:
                continue

            # check if case contains c
            if c.is_contain_by(case):
                dup_list.append(c)

        for c in dup_list:
            self.testcase_list.remove(c)

        # print("dup list: {}".format(dup_list))
        if len(dup_list) != 0:
            return True
        return False

    def get_total_exec_bb_count(self):
        count = 0
        for k in self.total_module_trace_info.keys():
            count += len(self.total_module_trace_info[k])

        return count

    def minimize(self, dir_path):
        # first load testcase from dir and generate trace for all file.
        count = 0
        for fname in os.listdir(dir_path):
            full_path = os.path.join(dir_path, fname)
            if os.path.isfile(full_path):

                shutil.copyfile(full_path, self.input_path_read_by_target)
                ret = self.exec_testcase(need_patch_to_file=self.patch_to_binary)

                if ret.status == ExecStatus.NORMAL:
                    self.save_testcase(ret.trace)
                    count += 1
                elif ret.status == ExecStatus.DOS:
                    self.save_dos(ret.trace)
                else:
                    self.save_crash(ret.trace, ret.crash_info)

        self.logger.log("[trapfuzzer] Before minimize, count: {}".format(count))

        total_bb_exected = self.get_total_exec_bb_count()

        if total_bb_exected == 0:
            shutil.rmtree(self.output)
            print("[trapfuzzer] No good testcase found!")
            return

        min_case_list = []
        total_trace_in_min_case = 0

        # find the max trace case
        while True:
            max_case = self.find_max_trace_case()
            total_trace_in_min_case = total_trace_in_min_case + max_case.get_trace_count()
            min_case_list.append(max_case)

            self.remove_dup_case(max_case)
            self.testcase_list.remove(max_case)

            if total_trace_in_min_case == total_bb_exected:
                break

        print("[trapfuzzer] After minimize, count: {}".format(len(min_case_list)))

        os.mkdir("{}/mini".format(self.output))
        for i in range(len(min_case_list)):
            c = min_case_list[i]
            src = "{}/trapfuzz-testcase-{}.bin".format(self.output, c.idx)
            dst = "{}/mini/trapfuzz-testcase-{}.bin".format(self.output, i)
            shutil.copyfile(src, dst)
            with open("{}/mini/trapfuzz-testcase-{}.trace".format(self.output, i), "wb") as fp:
                data = ""
                for ti in c.trace:
                    data += "{}\n".format(ti.module_name)
                    data += ','.join(['0x{:X}'.format(x) for x in ti.bb_list])
                    data += '\n'
                fp.write(data)

    def calc_file_md5(self, fpath):
        if not os.path.exists(fpath):
            return ""
        return hashlib.md5(open(fpath, 'rb').read()).hexdigest()

    def get_filelist(self, dir_path, need_sort=True):
        file_list = []
        dir_path = os.path.abspath(dir_path)
        for fname in os.listdir(dir_path):
            full_path = os.path.join(dir_path, fname)
            if os.path.isfile(full_path):
                if not os.path.basename(full_path).startswith("."):
                    file_size = os.path.getsize(full_path)

                    if file_size < self.min_testcase_size:
                        continue

                    file_list.append((full_path, file_size))

        if need_sort:
            file_list.sort(key=lambda x: x[1])

        ret = [x[0] for x in file_list]
        return ret

    def set_fuzz_stage(self, stage):
        self.exec_stage = stage
        with open(os.path.join(self.output, "exec-stage"), "w") as fp:
            fp.write(stage)

    def load_fuzz_stage(self):
        with open(os.path.join(self.output, "exec-stage"), "r") as fp:
            self.exec_stage = fp.read().strip()

    def load_testcase(self, dir_path):
        self.total_exec_count = 0
        count = 0

        self.set_fuzz_stage("loading-testcase")

        file_list = self.get_filelist(dir_path, False)
        testcase_log_fp = open(self.loaded_testcase_file, "a")

        round_count = len(file_list)
        for i in range(round_count):

            length = len(file_list)
            rnd_idx = random.randint(0, length - 1)
            full_path = file_list[rnd_idx]
            del file_list[rnd_idx]

            if self.fuzzer_status == "stop":
                self.logger.log("stop from load_testcase\n")
                exit(0)

            if self.loaded_testcase_list.has_key(os.path.basename(full_path)):
                continue

            c = 0
            while c < 3:
                try:
                    shutil.copyfile(full_path, self.input_path_read_by_target)
                    break
                except Exception as e:
                    c += 1
                    time.sleep(1)

                    print e

            if c >= 3:
                print("shutil.copyfile({}, {}) failed !".format(full_path, self.input_path_read_by_target))
                exit(0)

            self.current_file = full_path
            start = time.time()

            ret = self.exec_testcase(self.patch_to_binary)
            delta = time.time() - start


            if ret.status == ExecStatus.NORMAL:
                if self.has_new_path(ret.trace):
                    self.last_new_path_found = self.logger.get_current_time()
                    if self.patch_to_binary:
                        ret.trace = []
                    test_case = self.save_testcase(ret.trace)

                    if self.enable_database:
                        hash = self.calc_file_md5(self.input_path_read_by_target)
                        seed = self.db.get_seed(hash)
                        test_case.seed_hash = hash
                        if not seed:
                            fsize = os.path.getsize(self.input_path_read_by_target)
                            file_name = "trapfuzz-testcase-{}.bin".format(test_case.idx)
                            self.db.insert_new_seed("", hash, fsize, file_type=self.file_type, file_name=file_name)
                        else:
                            self.db.set_file_type(hash, "{}".format(self.file_type))

                    count += 1
            elif ret.status == ExecStatus.DOS:

                self.last_dos_found = self.logger.get_current_time()
                if self.save_dos(ret.trace, delta):
                    if self.enable_database:
                        hash = self.calc_file_md5(self.input_path_read_by_target)
                        seed = self.db.get_seed(hash)
                        if not seed:
                            fsize = os.path.getsize(self.input_path_read_by_target)
                            file_name = "trapfuzz-dos-{}.bin".format(len(self.dos_list) - 1)
                            self.db.insert_new_seed("", hash, fsize, file_type="{}-dos".format(self.file_type),
                                                    file_name=file_name, extra_info="exec-time: {} s".format(delta))
                        else:
                            self.db.set_file_type(hash, "{}-dos".format(self.file_type))
            else:
                self.last_crash_found = self.logger.get_current_time()
                self.logger.log("[trapfuzzer] found crash when load testcase!")
                if self.save_crash(ret.trace, ret.crash_info):
                    if self.enable_database:
                        hash = self.calc_file_md5(self.input_path_read_by_target)
                        seed = self.db.get_seed(hash)
                        if not seed:
                            fsize = os.path.getsize(self.input_path_read_by_target)
                            file_name = "trapfuzz-crash-{}.bin".format(len(self.crash_list) - 1)
                            self.db.insert_new_seed("", hash, fsize, file_type="{}-crash".format(self.file_type),
                                                    file_name=file_name, extra_info=ret.crash_info)
                        else:
                            self.db.set_file_type(hash, "{}-crash".format(self.file_type))

            if ret.status == ExecStatus.DOS:
                self.total_exec_time += self.avg_run_time
            else:
                self.total_exec_time += delta
            self.total_exec_count += 1
            if self.total_exec_count % 10 == 0:
                self.exec_speed = round(float(self.total_exec_count) / self.total_exec_time, 1)
                self.avg_run_time = round(float(self.total_exec_time) / self.total_exec_count, 1)
                self.logger.log("[trapfuzzer] run {}, speed:{}/min, avg_run_time:{}s, path count:{}".format(
                    self.total_exec_count, self.exec_speed * 60, self.avg_run_time, len(self.testcase_list)))

            self.loaded_testcase_list[os.path.basename(full_path)] = 1
            testcase_log_fp.write(os.path.basename(full_path) + "\n")
            testcase_log_fp.flush()

        testcase_log_fp.close()

        self.logger.log("[trapfuzzer] load {} testcase from {}!".format(count, dir_path))

        if not self.patch_to_binary:
            if count == 0:
                self.logger.log("[trapfuzzer] could not load testcase from {}, please check {} is patched!".format(
                    dir_path, ','.join(self.cov_module_name)))
                exit(1)

    def exec_testcase(self, need_patch_to_file=False, verbose=False):
        self.tracer.current_origin_seed = self.current_file
        self.tracer.current_input_file = self.input_path_read_by_target

        timeout = self.avg_run_time * self.timeout_ratio
            
        if timeout < 4 * self.timeout_ratio:
            timeout = 4 * self.timeout_ratio
            self.avg_run_time = 4
        
        if timeout > self.exec_timeout:
            timeout = self.exec_timeout

        return self.tracer.trace(need_patch_to_file, verbose, self.exit_basci_block, timeout)

    def save_testcase(self, bb_trace):
        testcase_idx = len(self.testcase_list)
        self.save_case_to_file("testcase", testcase_idx, bb_trace)
        testcase = Testcase(testcase_idx, bb_trace)
        self.testcase_list.append(testcase)
        return testcase

    def stop_fuzz(self):
        self.server_sock.close()
        self.tracer.quit()
        self.logger.log("exit fuzzer")

    def fuzz(self):

        if not self.resume_fuzzing and self.config.has_key("testcase"):
            if os.path.exists(self.config['testcase']):
                self.load_testcase(self.config['testcase'])
            else:
                self.logger.log("warning {} not exists!".format(self.config['testcase']))
                exit(1)

        if len(self.testcase_list) == 0:
            self.logger.log("No testcase found, exit fuzzer!")
            return

        self.total_exec_count = 0
        self.set_fuzz_stage("fuzz")

        self.cur_mutator = random.choice(self.mutator_list)

        while True:
            # seed = random.choice(self.testcase_list)
            for i in range(len(self.testcase_list)):

                if self.exec_stage == "loading-testcase":
                    self.load_testcase(self.import_case_dir)
                    self.set_fuzz_stage("fuzz")

                if self.patch_to_binary:
                    cur_seed = random.choice(self.testcase_list)
                else:
                    cur_seed = self.testcase_list[i]

                seed_path = "{}/trapfuzz-testcase-{}.bin".format(
                    self.output, cur_seed.idx)
                for i in range(cur_seed.exec_count):  # per case fuzz count
                    if self.fuzzer_status == "stop":
                        self.stop_fuzz()
                        return

                    run_time = time.time()
                    m_info = None
                    while True:
                        try:
                            m_info = self.cur_mutator.mutate(seed_path, self.input_path_read_by_target)
                            break
                        except:
                            # print "mutate file error, wait for retry..."
                            pass
                        time.sleep(0.5)

                    self.current_file = seed_path

                    try:
                        ret = self.exec_testcase(self.patch_to_binary)
                    except Exception as e:
                        print e
                        self.stop_fuzz()
                        return

                    delta = time.time() - run_time

                    if ret.status == ExecStatus.NORMAL:
                        if self.has_new_path(ret.trace):
                            self.last_new_path_found = self.logger.get_current_time()
                            if self.patch_to_binary:
                                ret.trace = []

                            test_case = self.save_testcase(ret.trace)

                            if self.enable_database:
                                hash = self.calc_file_md5(self.input_path_read_by_target)
                                seed = self.db.get_seed(hash)
                                test_case.seed_hash = hash
                                if not seed:
                                    fsize = os.path.getsize(self.input_path_read_by_target)
                                    file_name = "trapfuzz-testcase-{}.bin".format(test_case.idx)
                                    self.db.insert_new_seed(cur_seed.seed_hash, hash, fsize, file_type=self.file_type,
                                                            file_name=file_name, mutate_infomation=m_info)
                                else:
                                    self.db.set_file_type(hash, "{}".format(self.file_type))

                                self.db.inc_child_seed_count(cur_seed.seed_hash)

                            cur_seed.found_path()
                    elif ret.status == ExecStatus.DOS:
                        cur_seed.found_dos()
                        self.last_dos_found = self.logger.get_current_time()
                        if self.save_dos(ret.trace, delta):
                            if self.enable_database:
                                hash = self.calc_file_md5(self.input_path_read_by_target)
                                seed = self.db.get_seed(hash)
                                if not seed:
                                    fsize = os.path.getsize(self.input_path_read_by_target)
                                    file_name = "trapfuzz-dos-{}.bin".format(len(self.dos_list) - 1)
                                    self.db.insert_new_seed(cur_seed.seed_hash, hash, fsize,
                                                            file_type="{}-dos".format(self.file_type),
                                                            file_name=file_name, mutate_infomation=m_info,
                                                            extra_info="exec-time: {} s".format(delta))
                                else:
                                    self.db.set_file_type(hash, "{}-dos".format(self.file_type))

                                self.db.inc_dos_count(cur_seed.seed_hash)

                        self.logger.log("found a dos, seed index: {}".format(cur_seed.idx))
                        break
                    else:
                        self.last_crash_found = self.logger.get_current_time()
                        cur_seed.found_crash()
                        if self.save_crash(ret.trace, ret.crash_info):
                            if self.enable_database:
                                hash = self.calc_file_md5(self.input_path_read_by_target)
                                seed = self.db.get_seed(hash)
                                if not seed:
                                    fsize = os.path.getsize(self.input_path_read_by_target)
                                    file_name = "trapfuzz-crash-{}.bin".format(len(self.crash_list) - 1)
                                    self.db.insert_new_seed(cur_seed.seed_hash, hash, fsize,
                                                            file_type="{}-crash".format(self.file_type),
                                                            file_name=file_name, mutate_infomation=m_info,
                                                            extra_info=ret.crash_info)
                                else:
                                    self.db.set_file_type(hash, "{}-crash".format(self.file_type))

                                self.db.inc_crash_count(cur_seed.seed_hash)

                        self.logger.log("found a crash, seed index: {}".format(cur_seed.idx))

                    if ret.status == ExecStatus.DOS:
                        self.total_exec_time += self.avg_run_time
                    else:
                        self.total_exec_time += delta

                    self.total_exec_count += 1

                    if self.total_exec_count % 10 == 0:
                        self.cur_mutator = random.choice(self.mutator_list)
                        self.exec_speed = round(float(self.total_exec_count) / self.total_exec_time, 1)
                        self.avg_run_time = round(float(self.total_exec_time) / self.total_exec_count, 1)
                        self.logger.log("[trapfuzzer] run {}, speed:{}/min, avg_run_time:{}s, path count:{}".format(
                            self.total_exec_count, self.exec_speed * 60, self.avg_run_time, len(self.testcase_list)))


if __name__ == "__main__":
    config_filename = "config.json"
    if len(sys.argv) == 2:
        config_filename = sys.argv[1]
    fuzzer = Fuzzer(config_filename)
    # fuzzer.load_testcase("/home/hac425/wps_fuzzing/testcase/", need_patch_to_file=True)
    # fuzzer.minimize("testcase", True)
    fuzzer.fuzz()
    exit(0)
