import os
import shutil
import random

class MutatorBase:
    def myRand(self, min, max):
        val = ord(os.urandom(1)) * 0x100000 + ord(os.urandom(1)) * \
            0x10000 + ord(os.urandom(1)) * 0x100 + ord(os.urandom(1))
        return min + (val % (max-min+1))

    def isInXmlValue(self, f, pos, len):
        quotes = False
        f.seek(pos)
        for x in xrange(len):
            c = f.read(1)
            if c == "<" or c == ">" or c == "\"":
                return False

        c = f.read(1)
        quotes = 0
        while c != "" and c != None:
            if c == "\"":
                quotes += 1
            if c == ">":
                if quotes % 2 == 0:
                    return False
                else:
                    return True
            if c == "<":
                return True
            c = f.read(1)
        return False

    def restore(self, src, dest, signature):
        signatures = signature.split('|')
        if src != dest:
            shutil.copy2(src, dest)

        f = open(dest, "r+b")
        for sign in signatures:
            pos = int(sign[0:8], 16)
            val = int(sign[8:10], 16)
            f.seek(pos)
            f.write(chr(val))
        f.close()

    def setConf(self, conf):
        return True


class FileByteValues(MutatorBase):
    byteValues = [[0x00], [0xFF], [0xFE], [0xFF, 0xFF], [0xFF, 0xFE], [0xFE, 0xFF], [0xFF, 0xFF, 0xFF, 0xFF], [0xFF, 0xFF, 0xFF, 0xFE], [0xFE, 0xFF, 0xFF, 0xFF], [0x7F], [
        0x7E], [0x7F, 0xFF], [0x7F, 0xFE], [0xFF, 0x7F], [0xFE, 0x7F], [0x7F, 0xFF, 0xFF, 0xFF], [0x7F, 0xFF, 0xFF, 0xFE], [0xFF, 0xFF, 0xFF, 0x7F], [0xFE, 0xFF, 0xFF, 0x7F]]
    rate = 20000
    min = 2
    max = 100
    skip = 0

    def mutate(self, src, dest):
        ret_signature = []
        ret_text = ""
        r = []
        try:
            ret_text += "Mutating file %s into file %s using FileByteValues mutator\n\n" % (
                src, dest)
            if src != dest:
                shutil.copy2(src, dest)
            size = os.path.getsize(dest)
            count = int(round(size / self.rate))
            if int(count) < self.min:
                count = self.min
            if self.max > 0 and int(count) > self.max:
                count = self.max

            f = open(dest, "r+b")
            for x in xrange(int(count)):
                newVal = self.byteValues[self.myRand(
                    0, len(self.byteValues)-1)]
                pos = self.myRand(self.skip, size-len(newVal))
                for y in xrange(len(newVal)):
                    f.seek(pos+y)
                    oldVal = f.read(1)
                    f.seek(pos+y)
                    f.write(chr(newVal[y]))
                    ret_signature.append("%08X%02X%02X" %
                                         (pos+y, ord(oldVal), newVal[y]))

                    r.append("{:02X}".format(pos + y))

                    ret_text += "Mutating byte at 0x%X (%d) from 0x%02X to 0x%02X\n" % (
                        pos, pos, ord(oldVal), newVal[y])
            f.close()
        except:
            raise  # Just for now
            return None
        # return "|".join(ret_signature) + "\n" + ret_text

        return "|".join(r)

    def setConf(self, conf):
        if "rate" in conf:
            self.rate = conf["rate"]



class FileBitFlipping(MutatorBase):
    rate = 20000
    min = 2
    max = 100
    skip = 0

    def mutate(self, src, dest):
        ret_signature = []
        ret_text = ""
        r = []
        try:
            ret_text += "Mutating file %s into file %s using FileBitFlipping mutator\n\n" % (
                src, dest)
            if src != dest:
                shutil.copy2(src, dest)
            size = os.path.getsize(dest)
            count = int(round(size / self.rate))
            if int(count) < self.min:
                count = self.min
            if self.max > 0 and int(count) > self.max:
                count = self.max

            f = open(dest, "r+b")
            for x in xrange(int(count)):
                pos = self.myRand(self.skip, size-1)
                f.seek(pos)
                c = f.read(1)
                if c != None:
                    val = ord(c)
                    oldVal = val
                    f.seek(pos)
                    val = self.modify(val)
                    f.write(chr(val))
                    ret_signature.append("%08X%02X%02X" % (pos, oldVal, val))
                    ret_text += "Mutating byte at 0x%X (%d) from 0x%02X to 0x%02X\n" % (
                        pos, pos, oldVal, val)

                    r.append("{:02X}".format(pos))

            f.close()
        except:
            raise  # Just for now
            return None
        # return "|".join(ret_signature) + "\n" + ret_text

        return "|".join(r)

    def modify(self, byte):
        return byte ^ [1, 2, 4, 8, 16, 32, 64, 128][self.myRand(0, 7)]

    def setConf(self, conf):
        if "rate" in conf:
            self.rate = conf["rate"]

# come from https://github.com/FoxHex0ne/Vanapagan
class VanapaganMutator:
    __mutator_name__ = "VanapaganMutator"
    def __init__(self):
        self.mutator_list = []
        self.mutator_list.append(FileBitFlipping())
        self.mutator_list.append(FileByteValues())

    def mutate(self, input, output):
        mutator = random.choice(self.mutator_list)
        return mutator.mutate(input, output)



if __name__ == "__main__":
    mutator = VanapaganMutator()
    mutator.mutate("/home/hac425/code/example/0.bin", "/home/hac425/code/example/mutate.bin")