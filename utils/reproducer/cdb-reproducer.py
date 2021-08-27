import subprocess
from pycdb import PyCdb, PyCdbPipeClosedException, ExceptionEvent, ExitProcessEvent
import shutil
import os
import re


class CDBReproducer(PyCdb):

    def __init__(self, process_name=""):
        PyCdb.__init__(self)
        self.ignore_exceptions = [
            0x4000001f  # wow64 exception
        ]

        self.process_name = process_name
        self.windbg_dir = os.path.dirname(self.cdb_path)

    def config_page_heap(self, process_name, enable=True):
        gflags_path = os.path.join(self.windbg_dir, "gflags.exe")
        if enable:
            subprocess.call([gflags_path, "/p", "/enable", process_name])
        else:
            subprocess.call([gflags_path, "/p", "/disable", process_name])


    def calc_hash(self, trace):
        hash = ""
        for l in trace.split("\n"):
            l = l.lower().strip()
            if l == "" or "childebp " in l or "warning " in l:
                continue
            l = l.split(" ")

            hash += l[1][-3:]

        return hash

    def get_pc_hash(self, context):
        ret = ""
        try:
            ret = re.findall("eip=(.*?) ", context)[0][-3:]
        except:
            pass
        
        return ret

    def run(self):

        result = {}

        try:
            self.read_to_prompt()

            while True:
                self.continue_debugging()
                output = self.read_to_prompt()
                event = self.process_event()

                if type(event) == ExceptionEvent:
                    exception = event
                    if exception.code not in self.ignore_exceptions:
                        result['desc'] = "Exception %08X (%s) occured at %08X" % (
                            exception.code, exception.description, exception.address)

                        result['disas'] = self.execute("u @eip")
                        result['registers'] = self.execute("r")
                        result['stacktrace'] = self.execute("kb 8")
                        result['hash'] = self.get_pc_hash(result['registers']) + self.calc_hash(result['stacktrace'])
                        break


        except PyCdbPipeClosedException:
            print("pipe closed")

        except ExitProcessEvent:
            print("program closed")

        except Exception as ex:
            print(ex)


        return result


def save_result_to_file(result, fpath):
    with open(fpath, "w") as fp:
        r = "Desc:\n"
        r += result['desc']
        r += "\n" * 2

        r += "Disas:\n"
        r += result['disas']
        r += "\n"

        r += "Context:\n"
        r += result['registers']
        r += "\n"

        r += "Stack Trace:\n"
        r += result['stacktrace']
        r += "\n"

        r += "crash-hash: "
        r += result['hash']
        r += "\n"

        fp.write(r)





def reproduce(args, cases, input_file, output_dir):
    hash_list = []

    process_name = os.path.basename(args[0])

    print "target process name: {}".format(process_name)


    # enable page heap
    # dbg.config_page_heap(process_name)

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    else:
        for f in os.listdir(output_dir):
            fpath = os.path.join(output_dir, f)

            if ".info" not in fpath:
                continue

            if os.path.isfile(fpath):
                with open(fpath, "r") as fp:
                    try:
                        h = re.findall("crash-hash: (.*)", fp.read())[0]
                        hash_list.append(h)
                    except:
                        print fpath
                        pass

    count = 0

    for f in cases:

        count += 1

        dbg = CDBReproducer(process_name)
        dbg.add_cmdline_option("-y c:\\no_exist")
        dbg.read_to_prompt_timeout = 15

        if count == 1:
            dbg.config_page_heap(process_name)

        shutil.copyfile(f, input_file)
        dbg.spawn(args)
        # run the debug session
        result = dbg.run()

        subprocess.call(["taskkill", "/f", "/im", os.path.basename(args[0])], stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.call(["taskkill", "/f", "/im", "cdb.exe"], stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


        try:
            dbg.quit()
        except:
            pass

        if not result.has_key('hash'):
            continue

        h = result['hash']

        if h not in hash_list:
            base_name = os.path.basename(f).split(".")[0]
            save_result_to_file(result, "{}\\{}.info".format(output_dir, base_name))
            shutil.copyfile(input_file, "{}\\{}.bin".format(output_dir, base_name))

            hash_list.append(h)

if __name__ == "__main__":
    args = [ "C:\\Program Files (x86)\\JustSystems\\TARO31\\taro31.exe",
        "C:\\input.doc"]


    dir = "C:\\Users\\hac425\\Desktop\\crash-0618"

    files = []

    for i in os.listdir(dir):
        if "-crash-" in i and ".bin" in i:
            files.append(os.path.join(dir, i))
        
    # print len(files)
    # exit(0)
    reproduce(args, files, "C:\\input.doc", "crash-trige2\\")

