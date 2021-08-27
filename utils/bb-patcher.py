import subprocess
import os
import threading
from Queue import Empty

try:
    import queue
except ImportError:
    import Queue as queue
import shutil
from struct import pack, unpack


class AnalyseThread(threading.Thread):

    def __init__(self, ida_path, script_path, input_qeueue):
        threading.Thread.__init__(self)
        self.input_qeueue = input_qeueue
        self.ida_path = ida_path
        self.script_path = script_path

    def ida_analyse(self, ida_path, script_path, input_path):
        # print input_path
        command = '"{}" -A -c -S{} {}'.format(ida_path, os.path.abspath(script_path), input_path)
        print command
        p = subprocess.Popen(command, shell=True, cwd=os.getcwd())
        p.wait()

        if p.stdout:
            print p.stdout.read()

        if p.stderr:
            print p.stderr.read()

    def run(self):
        while True:
            try:
                input_path = self.input_qeueue.get_nowait()
                self.ida_analyse(self.ida_path, self.script_path, input_path)
            except Empty:
                break
            except Exception as e:
                print e
                break


def patch_bb(target, bb_file):
    d = os.path.dirname(target)
    output_dir = os.path.join(d, "patch")

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    output_file = os.path.join(output_dir, os.path.basename(target))
    shutil.copyfile(target, output_file)

    f = open(bb_file, "rb")
    fa = open(output_file, "r+b")
    rva_size = unpack("<I", f.read(4))[0]
    fname_sz = unpack("<I", f.read(4))[0]
    fname = f.read(fname_sz)

    count = 0

    while True:
        data = f.read(12)
        if len(data) < 12:
            break

        voff, foff, instr_sz = unpack("<III", data)
        instr = f.read(instr_sz)
        fa.seek(foff)
        fa.write("\xcc" * instr_sz)

        count += 1

    f.close()
    fa.close()

    print "patch {} basic block of {}".format(count, fname)


if __name__ == "__main__":

    ida_path = "E:\\software\\IDA_Pro_v7.5_Portable\\ida64.exe"
    input_dir = r"E:\vuln_data\wps_fuzzing\10702\wpp-bin"

    thread_count = 4

    dump_bb_script = "dump_bb.py"

    q = queue.Queue()

    for i in os.listdir(input_dir):
        file_path = os.path.join(input_dir, i)
        q.put(file_path)

    ths = []
    for i in range(thread_count):
        th = AnalyseThread(ida_path, dump_bb_script, q)
        th.start()
        ths.append(th)

    for i in ths:
        i.join()

    for i in os.listdir(input_dir):
        if "-bb.txt" in i:
            binary_file_path = os.path.join(input_dir, i[:-7])
            file_path = os.path.join(input_dir, i)
            patch_bb(binary_file_path, file_path)
