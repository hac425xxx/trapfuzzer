# /usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import random
import zipfile
import shutil
import hashlib


def calc_file_md5(fpath):
    if not os.path.exists(fpath):
        return ""
    return hashlib.md5(open(fpath, 'rb').read()).hexdigest()


class MemMutatorBase:
    rate = 20000
    min = 2
    max = 100
    skip = 0

    mutate_info = []

    def __init__(self):
        pass

    def myRand(self, min, max):
        val = ord(os.urandom(1)) * 0x100000 + ord(os.urandom(1)) * \
              0x10000 + ord(os.urandom(1)) * 0x100 + ord(os.urandom(1))
        return min + (val % (max - min + 1))

    def get_mutate_info(self):
        ar = []
        for i in self.mutate_info:
            ar.append("{:02X}".format(i))

        return "|".join(ar)

    def mutate(self, data):
        """
        :param data: bytearray
        :return: bytearray
        """

        pass


class ByteCopyMemMutator(MemMutatorBase):
    def __init__(self):
        pass

    def mutate(self, data):
        """
        取随机位置， 随机长度的数据，复制到随机位置， 覆盖
        """

        size = len(data)
        count = int(round(size / self.rate))
        if count < self.min:
            count = self.min
        if self.max > 0 and count > self.max:
            count = self.max

        remain_count = count
        while remain_count > 0:
            c = self.min
            if remain_count > self.min:
                c = self.myRand(self.min, remain_count)

            off_from = self.myRand(self.skip, size - c)
            off_to = self.myRand(self.skip, size - c)

            tmp = data[off_from: off_from + c]

            for x in xrange(c):
                data[off_to + x] = data[off_from + x]
                self.mutate_info.append(off_to + x)

            remain_count -= c

        return data


class InsertDataMemMutator(MemMutatorBase):
    def __init__(self):
        pass

    def mutate(self, data):
        """
        取随机位置， 随机长度的数据，插入到随机位置
        """

        size = len(data)
        count = int(round(size / self.rate))
        if count < self.min:
            count = self.min
        if self.max > 0 and count > self.max:
            count = self.max

        remain_count = count
        while remain_count > 0:
            c = self.min
            if remain_count > self.min:
                c = self.myRand(self.min, remain_count)

            off_from = self.myRand(self.skip, size - c)
            off_to = self.myRand(self.skip, size - 1)

            tmp = data[off_from: off_from + c]

            for i in range(c):
                data.insert(off_to + i, tmp[i])
                self.mutate_info.append(off_to + i)
            remain_count -= c
        return data


class ShrinkMemMutator(MemMutatorBase):
    def __init__(self):
        pass

    def mutate(self, data):
        """
        取随机位置， 随机长度的数据，插入到随机位置
        """

        size = len(data)
        count = int(round(size / self.rate))
        if count < self.min:
            count = self.min
        if self.max > 0 and count > self.max:
            count = self.max

        remain_count = count
        while remain_count > 0:
            c = self.min
            if remain_count > self.min:
                c = self.myRand(self.min, remain_count)

            off_from = self.myRand(self.skip, size - c)

            for i in range(c):
                self.mutate_info.append(off_from + i)

            for i in range(c):
                data.pop(off_from)

            remain_count -= c
        return data


class ByteValueMemMutator(MemMutatorBase):
    byteValues = [[0x00], [0xFF], [0xFE], [0xFF, 0xFF], [0xFF, 0xFE], [0xFE, 0xFF], [0xFF, 0xFF, 0xFF, 0xFF],
                  [0xFF, 0xFF, 0xFF, 0xFE], [0xFE, 0xFF, 0xFF, 0xFF], [0x7F], [
                      0x7E], [0x7F, 0xFF], [0x7F, 0xFE], [0xFF, 0x7F], [0xFE, 0x7F], [0x7F, 0xFF, 0xFF, 0xFF],
                  [0x7F, 0xFF, 0xFF, 0xFE], [0xFF, 0xFF, 0xFF, 0x7F], [0xFE, 0xFF, 0xFF, 0x7F]]

    def mutate(self, data):

        size = len(data)
        count = int(round(size / self.rate))
        if count < self.min:
            count = self.min
        if self.max > 0 and count > self.max:
            count = self.max

        for x in xrange(count):
            newVal = self.byteValues[self.myRand(0, len(self.byteValues) - 1)]
            pos = self.myRand(self.skip, size - len(newVal))
            for y in xrange(len(newVal)):
                data[pos + y] = newVal[y]
                self.mutate_info.append(pos + y)

        return data


class BitFlippingMemMutator(MemMutatorBase):

    def __init__(self):
        pass

    def flipping(self, byte):
        return byte ^ [1, 2, 4, 8, 16, 32, 64, 128][self.myRand(0, 7)]

    def mutate(self, data):

        size = len(data)
        count = int(round(size / self.rate))
        if count < self.min:
            count = self.min
        if self.max > 0 and count > self.max:
            count = self.max

        for x in xrange(count):
            pos = self.myRand(self.skip, size - 1)
            d = data[pos]
            flip_d = self.flipping(d)
            data[pos] = chr(flip_d)

            self.mutate_info.append(pos)
        return data


class BinaryMemMutator:
    __mutator_name__ = "BinaryContentMutator"

    def __init__(self):
        self.mutator_list = []
        self.mutator_list.append(ByteValueMemMutator())
        self.mutator_list.append(InsertDataMemMutator())
        self.mutator_list.append(ShrinkMemMutator())
        self.mutator_list.append(ByteCopyMemMutator())
        self.mutator_list.append(BitFlippingMemMutator())

        self.mutate_info = ""

    def mutate(self, input):
        mutator = random.choice(self.mutator_list)
        b = mutator.mutate(input)
        self.mutate_info = mutator.get_mutate_info()
        return b


class OpenXMLMutator:

    def __init__(self, input_file, output, extract_dir):
        self.extract_dir = extract_dir
        self.input_file = input_file
        self.extract(self.input_file, self.extract_dir)
        self.file_content_dict = self.load_to_memory(self.extract_dir)
        self.output = output
        self.mutator = BinaryMemMutator()

        self.current_mutate_file = ""

    def get_mutate_info(self):
        return "{}|{}".format(self.current_mutate_file, self.mutator.mutate_info)

    def load_to_memory(self, extract_dir):
        file_content_dict = {}
        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                dir_name = root[len(extract_dir) + 1:]
                with open(os.path.join(root, file_name), "rb") as fp:
                    file_content_dict[os.path.join(dir_name, file_name)] = fp.read()
        return file_content_dict

    def extract(self, path_to_zip_file, directory_to_extract_to, overwrite=True):

        if overwrite and os.path.exists(directory_to_extract_to):
            shutil.rmtree(directory_to_extract_to)

        try:
            zip_ref = zipfile.ZipFile(path_to_zip_file, 'r')
            zip_ref.extractall(directory_to_extract_to)
            zip_ref.close()
        except Exception as e:
            print e

    def pack(self, output):
        zf = zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED)
        for k in self.file_content_dict.keys():
            # content = str(self.file_content_dict[k])
            content = self.file_content_dict[k]
            zf.writestr(k, content, zipfile.ZIP_DEFLATED)

    def packfile(self, output, dir):
        zf = zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(dir):
            for file_name in files:
                dir_name = root[len(dir) + 1:]
                with open(os.path.join(root, file_name), "rb") as fp:
                    zf.writestr(os.path.join(dir_name, file_name), fp.read(), zipfile.ZIP_DEFLATED)

    def mutate(self):

        keys = self.file_content_dict.keys()

        k = random.choice(keys)
        content = self.file_content_dict[k]
        bak = content

        content = str(self.mutator.mutate(bytearray(content)))

        self.file_content_dict[k] = content
        self.pack(self.output)

        self.file_content_dict[k] = bak

        self.current_mutate_file = k

        # print "mutate: {}".format(k)


if __name__ == "__main__":

    # x.packfile("o.docx", os.path.abspath("ooo"))

    # hash = calc_file_md5("d.docx")
    # db.insert_new_seed(0, hash, os.path.getsize("d.docx"), 0, 0, 0, "docx", "d.docx", "")
    # exit(1)

    s = db.get_seed("8243214b2adc98e256dad620948da6d5")

    # x.pack("o.docx")
    for i in range(3):
        x = OpenXMLMutator(s.file_name, "o.docx", "ooo")
        x.mutate()
        hash = calc_file_md5(x.output)
    exit(1)

    x = ByteCopyMemMutator()
    x = ByteValueMemMutator()
    x = InsertDataMemMutator()
    x = ShrinkMemMutator()

    x = BitFlippingMemMutator()

    # x = CustomMutator()

    import re

    for i in range(100000):
        input = bytearray("<sss>dddd<sss>  <ax:sss>dddd<ax:sss> <cs:www>fdd<cs:www>")

        print len(input)
        print repr(input)

        for i in range(4):
            input = x.mutate(input)

        print len(input)
        print repr(input)

        with open("o.bin", "wb") as fp:
            fp.write(input)

    print "okkk"
