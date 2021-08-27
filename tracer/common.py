from enum import Enum
import hashlib
import datetime
import json
import re

BASE_CMD = 0x1110
AGENT_HELLO_CMD = BASE_CMD
GET_AGENT_PID = BASE_CMD + 1
RUN_TESTCASE = BASE_CMD + 2
RESTART_AGENT = BASE_CMD + 3
WRITE_TRACE_RESULT = BASE_CMD + 4


class ExecStatus(Enum):
    NORMAL = 0xd0
    CRASH = NORMAL + 1
    ABORT = NORMAL + 2
    DOS = NORMAL + 3


class TraceInfo:
    def __init__(self, module_name, bb_list):
        self.module_name = module_name
        self.bb_list = bb_list

    def to_dict(self):
        ret = {}
        ret['module_name'] = self.module_name
        ret['bb_list'] = self.bb_list
        return ret

    def to_json(self):
        return json.dumps(self.to_dict())


class ExecResult:
    def __init__(self, trace=[], status="", crash_info=""):
        self.trace = trace  # TraceInfo list
        self.status = status
        self.crash_info = crash_info

    def is_crash(self):
        if self.status == 0xd0:
            return True
        else:
            return False

    def to_json(self):
        ret = {}
        ret['status'] = self.status.value
        ret['crash_info'] = self.crash_info
        ret['trace'] = []

        for ti in self.trace:
            ret['trace'].append(ti.to_dict())

        return json.dumps(ret)

    def load_json(self, data):
        data = json.loads(data)
        self.status = ExecStatus(data['status'])

        self.crash_info = data['crash_info']
        self.trace = []

        for t in data['trace']:
            self.trace.append(TraceInfo(t['module_name'], t['bb_list']))

    def __str__(self):
        return "status: {}, crash_info: {}".format(self.status, self.crash_info)


class Testcase:
    def __init__(self, idx, bb_executed):
        self.idx = idx
        self.trace = bb_executed
        self.base_exec_count = 50
        self.exec_count = self.base_exec_count
        self.path_found = 0  # new path found by this case
        self.dos_count = 0

        self.crash_count = 0

        self.seed_id = 0
        self.seed_hash = ""

        self.inc_ratio = 0.1
        self.dec_ratio = 0.1

    def get_trace(self):
        return self.trace

    def get_trace_count(self):
        count = 0
        for ti in self.trace:
            count += len(ti.bb_list)
        return count

    def is_contain_by(self, seed):
        for i in range(self.trace):
            a = set(self.trace[i].bb_list)
            b = set(seed.trace[i].bb_list)
            if not b.issuperset(a):
                return False
        return True

    def found_crash(self):
        self.crash_count += 1

    def found_dos(self):
        self.exec_count = int(self.exec_count * self.dec_ratio)
        if self.exec_count == 0:
            self.exec_count = 1
        self.dos_count += 1

    def found_path(self):
        self.path_found += 1
        self.exec_count = int(self.base_exec_count + self.base_exec_count * self.path_found * self.inc_ratio)

    def __str__(self):
        data = "idx: {}, crash found: {}, dos found: {}, path found: {}, bb count: {}, exec count: {}".format(
            self.idx, self.crash_count, self.dos_count, self.path_found, self.get_trace_count(), self.exec_count)
        return data


class Crash:
    def __init__(self, idx, trace, crash_info=""):
        self.idx = idx
        self.trace = trace
        self.crash_info = crash_info

        data = ""
        for ti in trace:
            data += "{}\n".format(ti.module_name)
            data += ','.join(['{:X}'.format(x) for x in ti.bb_list])
            data += '\n'

        crash_hash = self.parse_crash_hash(crash_info)

        if crash_hash:
            self.trace_hash = crash_hash[:18]  # max depth is 6
        else:
            self.trace_hash = hashlib.md5(data + crash_info).hexdigest()

    def parse_crash_hash(self, crash_info):
        pc = None
        try:
            d = re.findall("crash-hash: (.*?) ", crash_info)
            if len(d) > 0:
                return d[0]

            d = re.findall("eip=(.*?) ", crash_info)
            if len(d) > 0:
                return d[0][-3:]

            d = re.findall("rip\s+(.*?) ", crash_info)
            if len(d) > 0:
                return d[0][-3:]

            d = re.findall("eip\s+(.*?) ", crash_info)
            if len(d) > 0:
                return d[0][-3:]
        except Exception as e:
            print "get_crash_hash_from_crash_info failed"
            print e
            print crash_info
        return pc


class Dos:
    def __init__(self, idx, trace, exec_time=-1):
        self.idx = idx
        self.trace = trace

        data = ""

        for ti in trace:
            data += "{}\n".format(ti.module_name)
            data += ','.join(['{:X}'.format(x) for x in ti.bb_list])
            data += '\n'

        self.trace_hash = hashlib.md5(data).hexdigest()


class CustomLogger:
    def __init__(self):
        pass

    def get_current_time(self):
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def log(self, s):
        data = "[{}] {}".format(self.get_current_time(), s)
        print(data)
