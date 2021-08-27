#!/usr/bin/env python
# encoding: utf-8

import random
from struct import pack, unpack
import socket
from time import sleep
import os

CHAR_LIST = ["\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0a", "\x0b", "\x0c",
             "\x0d", "\x0e", "\x0f", "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17", "\x18", "\x19",
             "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f", "\x20", "\x21", "\x22", "\x23", "\x24", "\x25", "\x26",
             "\x27", "\x28", "\x29", "\x2a", "\x2b", "\x2c", "\x2d", "\x2e", "\x2f", "\x30", "\x31", "\x32", "\x33",
             "\x34", "\x35", "\x36", "\x37", "\x38", "\x39", "\x3a", "\x3b", "\x3c", "\x3d", "\x3e", "\x3f", "\x40",
             "\x41", "\x42", "\x43", "\x44", "\x45", "\x46", "\x47", "\x48", "\x49", "\x4a", "\x4b", "\x4c", "\x4d",
             "\x4e", "\x4f", "\x50", "\x51", "\x52", "\x53", "\x54", "\x55", "\x56", "\x57", "\x58", "\x59", "\x5a",
             "\x5b", "\x5c", "\x5d", "\x5e", "\x5f", "\x60", "\x61", "\x62", "\x63", "\x64", "\x65", "\x66", "\x67",
             "\x68", "\x69", "\x6a", "\x6b", "\x6c", "\x6d", "\x6e", "\x6f", "\x70", "\x71", "\x72", "\x73", "\x74",
             "\x75", "\x76", "\x77", "\x78", "\x79", "\x7a", "\x7b", "\x7c", "\x7d", "\x7e", "\x7f", "\x80", "\x81",
             "\x82", "\x83", "\x84", "\x85", "\x86", "\x87", "\x88", "\x89", "\x8a", "\x8b", "\x8c", "\x8d", "\x8e",
             "\x8f", "\x90", "\x91", "\x92", "\x93", "\x94", "\x95", "\x96", "\x97", "\x98", "\x99", "\x9a", "\x9b",
             "\x9c", "\x9d", "\x9e", "\x9f", "\xa0", "\xa1", "\xa2", "\xa3", "\xa4", "\xa5", "\xa6", "\xa7", "\xa8",
             "\xa9", "\xaa", "\xab", "\xac", "\xad", "\xae", "\xaf", "\xb0", "\xb1", "\xb2", "\xb3", "\xb4", "\xb5",
             "\xb6", "\xb7", "\xb8", "\xb9", "\xba", "\xbb", "\xbc", "\xbd", "\xbe", "\xbf", "\xc0", "\xc1", "\xc2",
             "\xc3", "\xc4", "\xc5", "\xc6", "\xc7", "\xc8", "\xc9", "\xca", "\xcb", "\xcc", "\xcd", "\xce", "\xcf",
             "\xd0", "\xd1", "\xd2", "\xd3", "\xd4", "\xd5", "\xd6", "\xd7", "\xd8", "\xd9", "\xda", "\xdb", "\xdc",
             "\xdd", "\xde", "\xdf", "\xe0", "\xe1", "\xe2", "\xe3", "\xe4", "\xe5", "\xe6", "\xe7", "\xe8", "\xe9",
             "\xea", "\xeb", "\xec", "\xed", "\xee", "\xef", "\xf0", "\xf1", "\xf2", "\xf3", "\xf4", "\xf5", "\xf6",
             "\xf7", "\xf8", "\xf9", "\xfa", "\xfb", "\xfc", "\xfd", "\xfe", "\xff"]


def p8(d):
    """Return d packed as 8-bit unsigned integer (little endian)."""
    d = d & 0xff
    return pack('<B', d)


def u8(d):
    """Return the number represented by d when interpreted as a 8-bit unsigned integer (little endian)."""
    return unpack('<B', d)[0]


def p16(d, big_endian=False):
    """Return d packed as 16-bit unsigned integer (little endian)."""
    d = d & 0xffff
    if big_endian:
        return pack('>H', d)
    else:
        return pack('<H', d)


def u16(d, big_endian=False):
    """Return the number represented by d when interpreted as a 16-bit unsigned integer (little endian)."""

    if big_endian:
        return unpack('>H', d)[0]
    else:
        return unpack('<H', d)[0]


def p32(d):
    """Return d packed as 32-bit unsigned integer (little endian)."""
    d = d & 0xffffffff
    return pack('<I', d)


def u32(d):
    """Return the number represented by d when interpreted as a 32-bit unsigned integer (little endian)."""
    return unpack('<I', d)[0]


def p64(d):
    """Return d packed as 64-bit unsigned integer (little endian)."""
    d = 0xffffffffffffffff
    return pack('<Q', d)


def u64(d):
    """Return the number represented by d when interpreted as a 64-bit unsigned integer (little endian)."""
    return unpack('<Q', d)[0]


def hexdump(src, length=16):
    filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and filter[ord(x)]) or '.') for x in chars])
        lines.append("%-*s  %s\n" % (length * 3, hex, printable))
    print(''.join(lines))


def get_random_string(len):
    """ 获取len长度的随机字符串"""
    res = ""
    for i in xrange(len):
        res += random.choice(CHAR_LIST)
    return res


def insert_string(src, str_to_insert, index):
    """
    函数的作用： 在 index 插入 字符串
    :param string: 原始字符串
    :param str_to_insert:  将要插入的字符串
    :param index: 插入的位置
    :return: 插入后形成的字符串
    """

    # 如果 index 越界就返回空
    if index > len(src):
        return ""

    if index == len(src):
        return src + str_to_insert

    return src[:index] + str_to_insert + src[index:]


def replace_string(src, replacement='', index=0):
    """

    :param src:  原始字符串
    :param replacement:  要覆盖的字符串
    :param index:  覆盖的起始位置
    :return:   覆盖后的字符串
    """

    rlen = len(replacement)
    # 如果 index 越界就返回空
    # 在上层确保不要越界以提升变异的效率
    if rlen + index > len(src):
        return ""

    return src[:index] + replacement + src[index + rlen:]


def generate_preseqs(trans, idx):
    """
    利用 trans 生成到待测状态 idx, 需要的前序包
    :param trans: 所有的 trans 字典
    :param idx: 待测状态的索引
    :return:[{"send":"xxx", "recv":"kkkk"}]
    """
    seqs = []
    for i in xrange(idx):
        seq = {}
        seq['send'] = trans[i]['send']
        seq['recv'] = trans[i]['recv']
        seqs.append(seq)
    return seqs



MANGLE_FUNCS = [
    # 0: lambda data: mangle_resize(data),
    # 1: lambda data: mangle_byte(data),
    lambda data: mangle_bit(data),
    lambda data: mangle_bytes(data),
    lambda data: mangle_magic(data),
    # 5: lambda data: mangle_incbyte(data),
    # 6: lambda data: mangle_decbyte(data),
    # 7: lambda data: mangle_negbyte(data),
    # 8: lambda data: mangle_add_sub(data),
    lambda data: mangle_mem_copy(data),
    lambda data: mangle_mem_insert(data),
    lambda data: mangle_memset_max(data),
    lambda data: mangle_random(data),
    lambda data: mangle_clonebyte(data),
    lambda data: mangle_expand(data),
    lambda data: mangle_shrink(data),
    lambda data: mangle_insert_rnd(data),
    # lambda data: mangle_copy_token(data),
    # lambda data: mangle_insert_token(data),
]

TOKEN = []


def mangle_copy_token(data):
    """往随机位置用 token 覆盖数据 """
    ret = data
    if TOKEN:

        length = len(data)
        # 选择一个 token 插入
        midx = random.randint(0, len(TOKEN) - 1)
        mlen = len(TOKEN[midx])

        #  如果 选中的 token 的长度大于 data 的长度就不变异了
        if mlen >= length:
            return data

        # 获取插入位置, token - mlen 确保不会越界
        idx = random.randint(0, length - mlen)
        #  获取 token , 然后插入进去
        ret = replace_string(data, TOKEN[midx], idx)
    else:
        ret = data
    return ret


def mangle_insert_token(data):
    """
    往随机位置用 token 覆盖数据
    """
    ret = data
    if TOKEN:

        length = len(data)
        # 选择一个 token 插入
        idx = random.randint(0, len(TOKEN) - 1)
        off_to = random.randint(0, length)

        ret = insert_string(data, TOKEN[idx], off_to)
    else:
        ret = data
    return ret


def mangle_resize(data):
    """ 用空格填充随机位置 """
    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length)
    # 获取插入位置, length - size 确保不会越界
    idx = random.randint(0, length - size)

    return replace_string(data, " " * size, idx)


def mangle_byte(data):
    """
    往随机位置写随机 一字节数据
    """
    data = list(data)
    length = len(data)
    off = random.randint(0, length - 1)
    data[off] = chr(random.randint(0, 0xff))
    return "".join(data)


def mangle_bit(data):
    """
    取随机位置的数值做位翻转
    """
    data = list(data)
    length = len(data)
    off = random.randint(0, length - 1)

    # 从随机位置取出一个字节，后续来做位翻转
    byte = ord(data[off])

    # 从 byte 中随机取一位做 位翻转 ， 利用  1 和异或的特性
    data[off] = chr(byte ^ (1 << random.randint(0, 7)))
    return "".join(data)


def mangle_bytes(data):
    """
    在随机位置覆盖写2~4字节数据
    """

    length = len(data)

    if length < 4:
        return data

    # 获取要填充的数据的长度
    size = random.randint(2, 4)

    # 获取插入位置, length - size 确保不会越界
    idx = random.randint(0, length - size)
    #  获取 size 长的随机字符串， 然后复写到指定位置
    return replace_string(data, get_random_string(size), idx)


def mangle_magic(data):
    """
    对随机位置的字符串采用 边界值来替换
    """

    # 里面包含了各种边界值， 1, 2, 4, 8 字节， 供程序选择
    magic_string = [
        #  1 字节 的数据
        "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0A", "\x0B", "\x0C",
        "\x0D", "\x0E", "\x0F", "\x10", "\x20", "\x40", "\x7E", "\x7F", "\x80", "\x81", "\xC0", "\xFE", "\xFF",

        #  2 字节的数据
        "\x00\x00", "\x01\x01", "\x80\x80", "\xFF\xFF", "\x00\x01", "\x00\x02", "\x00\x03", "\x00\x04",
        "\x00\x05", "\x00\x06", "\x00\x07", "\x00\x08", "\x00\x09", "\x00\x0A", "\x00\x0B", "\x00\x0C",
        "\x00\x0D", "\x00\x0E", "\x00\x0F", "\x00\x10", "\x00\x20", "\x00\x40", "\x00\x7E", "\x00\x7F",
        "\x00\x80", "\x00\x81", "\x00\xC0", "\x00\xFE", "\x00\xFF", "\x7E\xFF", "\x7F\xFF", "\x80\x00",
        "\x80\x01", "\xFF\xFE", "\x00\x00", "\x01\x00", "\x02\x00", "\x03\x00", "\x04\x00", "\x05\x00",
        "\x06\x00", "\x07\x00", "\x08\x00", "\x09\x00", "\x0A\x00", "\x0B\x00", "\x0C\x00", "\x0D\x00",
        "\x0E\x00", "\x0F\x00", "\x10\x00", "\x20\x00", "\x40\x00", "\x7E\x00", "\x7F\x00", "\x80\x00",
        "\x81\x00", "\xC0\x00", "\xFE\x00", "\xFF\x00", "\xFF\x7E", "\xFF\x7F", "\x00\x80", "\x01\x80",
        "\xFE\xFF",

        # 4 字节
        "\x00\x00\x00\x00", "\x01\x01\x01\x01", "\x80\x80\x80\x80", "\xFF\xFF\xFF\xFF",
        "\x00\x00\x00\x01", "\x00\x00\x00\x02", "\x00\x00\x00\x03", "\x00\x00\x00\x04", "\x00\x00\x00\x05",
        "\x00\x00\x00\x06", "\x00\x00\x00\x07", "\x00\x00\x00\x08", "\x00\x00\x00\x09", "\x00\x00\x00\x0A",
        "\x00\x00\x00\x0B", "\x00\x00\x00\x0C", "\x00\x00\x00\x0D", "\x00\x00\x00\x0E", "\x00\x00\x00\x0F",
        "\x00\x00\x00\x10", "\x00\x00\x00\x20", "\x00\x00\x00\x40", "\x00\x00\x00\x7E", "\x00\x00\x00\x7F",
        "\x00\x00\x00\x80", "\x00\x00\x00\x81", "\x00\x00\x00\xC0", "\x00\x00\x00\xFE", "\x00\x00\x00\xFF",
        "\x7E\xFF\xFF\xFF", "\x7F\xFF\xFF\xFF", "\x80\x00\x00\x00", "\x80\x00\x00\x01", "\xFF\xFF\xFF\xFE",
        "\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x03\x00\x00\x00", "\x04\x00\x00\x00",
        "\x05\x00\x00\x00", "\x06\x00\x00\x00", "\x07\x00\x00\x00", "\x08\x00\x00\x00", "\x09\x00\x00\x00",
        "\x0A\x00\x00\x00", "\x0B\x00\x00\x00", "\x0C\x00\x00\x00", "\x0D\x00\x00\x00", "\x0E\x00\x00\x00",
        "\x0F\x00\x00\x00", "\x10\x00\x00\x00", "\x20\x00\x00\x00", "\x40\x00\x00\x00", "\x7E\x00\x00\x00",
        "\x7F\x00\x00\x00", "\x80\x00\x00\x00", "\x81\x00\x00\x00", "\xC0\x00\x00\x00", "\xFE\x00\x00\x00",
        "\xFF\x00\x00\x00", "\xFF\xFF\xFF\x7E", "\xFF\xFF\xFF\x7F", "\x00\x00\x00\x80", "\x01\x00\x00\x80",
        "\xFE\xFF\xFF\xFF",

        # 8 字节
        "\x00\x00\x00\x00\x00\x00\x00\x00", "\x01\x01\x01\x01\x01\x01\x01\x01",
        "\x80\x80\x80\x80\x80\x80\x80\x80", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        "\x00\x00\x00\x00\x00\x00\x00\x01", "\x00\x00\x00\x00\x00\x00\x00\x02",
        "\x00\x00\x00\x00\x00\x00\x00\x03", "\x00\x00\x00\x00\x00\x00\x00\x04",
        "\x00\x00\x00\x00\x00\x00\x00\x05", "\x00\x00\x00\x00\x00\x00\x00\x06",
        "\x00\x00\x00\x00\x00\x00\x00\x07", "\x00\x00\x00\x00\x00\x00\x00\x08",
        "\x00\x00\x00\x00\x00\x00\x00\x09", "\x00\x00\x00\x00\x00\x00\x00\x0A",
        "\x00\x00\x00\x00\x00\x00\x00\x0B", "\x00\x00\x00\x00\x00\x00\x00\x0C",
        "\x00\x00\x00\x00\x00\x00\x00\x0D", "\x00\x00\x00\x00\x00\x00\x00\x0E",
        "\x00\x00\x00\x00\x00\x00\x00\x0F", "\x00\x00\x00\x00\x00\x00\x00\x10",
        "\x00\x00\x00\x00\x00\x00\x00\x20", "\x00\x00\x00\x00\x00\x00\x00\x40",
        "\x00\x00\x00\x00\x00\x00\x00\x7E", "\x00\x00\x00\x00\x00\x00\x00\x7F",
        "\x00\x00\x00\x00\x00\x00\x00\x80", "\x00\x00\x00\x00\x00\x00\x00\x81",
        "\x00\x00\x00\x00\x00\x00\x00\xC0", "\x00\x00\x00\x00\x00\x00\x00\xFE",
        "\x00\x00\x00\x00\x00\x00\x00\xFF", "\x7E\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "\x80\x00\x00\x00\x00\x00\x00\x00",
        "\x80\x00\x00\x00\x00\x00\x00\x01", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE",
        "\x00\x00\x00\x00\x00\x00\x00\x00", "\x01\x00\x00\x00\x00\x00\x00\x00",
        "\x02\x00\x00\x00\x00\x00\x00\x00", "\x03\x00\x00\x00\x00\x00\x00\x00",
        "\x04\x00\x00\x00\x00\x00\x00\x00", "\x05\x00\x00\x00\x00\x00\x00\x00",
        "\x06\x00\x00\x00\x00\x00\x00\x00", "\x07\x00\x00\x00\x00\x00\x00\x00",
        "\x08\x00\x00\x00\x00\x00\x00\x00", "\x09\x00\x00\x00\x00\x00\x00\x00",
        "\x0A\x00\x00\x00\x00\x00\x00\x00", "\x0B\x00\x00\x00\x00\x00\x00\x00",
        "\x0C\x00\x00\x00\x00\x00\x00\x00", "\x0D\x00\x00\x00\x00\x00\x00\x00",
        "\x0E\x00\x00\x00\x00\x00\x00\x00", "\x0F\x00\x00\x00\x00\x00\x00\x00",
        "\x10\x00\x00\x00\x00\x00\x00\x00", "\x20\x00\x00\x00\x00\x00\x00\x00",
        "\x40\x00\x00\x00\x00\x00\x00\x00", "\x7E\x00\x00\x00\x00\x00\x00\x00",
        "\x7F\x00\x00\x00\x00\x00\x00\x00", "\x80\x00\x00\x00\x00\x00\x00\x00",
        "\x81\x00\x00\x00\x00\x00\x00\x00", "\xC0\x00\x00\x00\x00\x00\x00\x00",
        "\xFE\x00\x00\x00\x00\x00\x00\x00", "\xFF\x00\x00\x00\x00\x00\x00\x00",
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7E", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F",
        "\x00\x00\x00\x00\x00\x00\x00\x80", "\x01\x00\x00\x00\x00\x00\x00\x80",
        "\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    ]

    length = len(data)
    # 选择一个 magic_string 插入
    midx = random.randint(0, len(magic_string) - 1)
    mlen = len(magic_string[midx])

    #  如果 选中的 magic_string 的长度大于 data 的长度就不变异了
    if mlen >= length:
        return data

    # 获取插入位置, length - mlen 确保不会越界
    idx = random.randint(0, length - mlen)
    #  获取 magic_string , 然后插入进去
    return replace_string(data, magic_string[midx], idx)


def mangle_incbyte(data):
    """
    取随机位置的数值 加 1
    """
    data = list(data)
    length = len(data)
    off = random.randint(0, length - 1)

    # 随机取出字符，然后加1
    data[off] = chr((ord(data[off]) + 1) & 0xff)
    return "".join(data)


def mangle_decbyte(data):
    """
    取随机位置的数值 减 1
    """
    data = list(data)
    length = len(data)
    off = random.randint(0, length - 1)

    # 随机取出字符，然后减1
    # print("{}==>{}".format(off, hex(ord(data[off]))))
    data[off] = chr((ord(data[off]) - 1) & 0xff)

    return "".join(data)


def mangle_negbyte(data):
    """
    取随机位置的数值 取反
    """
    data = list(data)
    length = len(data)
    off = random.randint(0, length - 1)

    # 随机取出字符，然后取反， 注意只要最低 8 字节
    data[off] = chr((~ord(data[off])) & 0xff)
    return "".join(data)


def mangle_add_sub(data):
    """
    取随机位置的1 , 2, 4 或者8 字节做加减操作
    """

    length = len(data)
    #  选择变量长度
    var_len = 1 << random.randint(0, 3)

    if length < var_len:
        return data

    off = random.randint(0, length - var_len)

    # 操作数
    delta = random.randint(0, 8192) - 4096

    if var_len == 1:
        c = u8(data[off: off + var_len])
        if delta & 1:
            c = c + delta
        else:
            c = c - delta
        data = replace_string(data, p8(c), off)
    elif var_len == 2:
        c = u16(data[off: off + var_len])
        if delta & 1:
            c = c + delta
        else:
            c = c - delta

        data = replace_string(data, p16(c), off)

    elif var_len == 4:
        c = u32(data[off: off + var_len])
        if delta & 1:
            c = c + delta
        else:
            c = c - delta

        data = replace_string(data, p32(c), off)

    else:
        c = u64(data[off: off + var_len])
        if delta & 1:
            c = c + delta
        else:
            c = c - delta
        data = replace_string(data, p64(c), off)

    return data


def mangle_mem_copy(data):
    """
    取随机位置， 随机长度的数据，复制到随机位置， 覆盖
    """

    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)

    off_from = random.randint(0, length - size)
    off_to = random.randint(0, length - size)

    return replace_string(data, data[off_from:off_from + size], off_to)


def mangle_mem_insert(data):
    """
    取随机位置， 随机长度的数据，插入到随机位置
    """

    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)

    off_from = random.randint(0, length - size)
    off_to = random.randint(0, length)

    return insert_string(data, data[off_from:off_from + size], off_to)


def mangle_memset_max(data):
    """  在随机位置填充随机长度的 特殊字符， 0xff, 0x7f ....... """
    # https://security.tencent.com/index.php/blog/msg/35
    special_char = ['\x00', '\xFF', '\x3F', '\x7F', '\x80', '\xFE', '\x60']
    byte = special_char[random.randint(0, len(special_char) - 1)]
    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)
    off = random.randint(0, length - size)
    return replace_string(data, byte * size, off)


def mangle_random(data):
    """  取随机位置、随机大小的缓冲区，用随机数填充 """

    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)
    off = random.randint(0, length - size)
    return replace_string(data, get_random_string(size), off)


def mangle_clonebyte(data):
    """
    取两处随机位置的作数据交换
    """

    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)

    off_from = random.randint(0, length - size)
    data_from = data[off_from:off_from + size]

    off_to = random.randint(0, length - size)
    data_to = data[off_to:off_to + size]
    data = replace_string(data, data_from, off_to)
    data = replace_string(data, data_to, off_from)
    return data


def mangle_expand(data):
    """
    在随机位置，取随机长度的数据追加到数据末尾
    """

    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)
    off = random.randint(0, length - size)

    return data + data[off:off + size]


def mangle_shrink(data):
    """
    随机删减内容
    """

    length = len(data)
    # 获取要填充的数据的长度
    size = random.randint(0, length - 1)
    off = random.randint(0, length - size)
    return data[:off] + data[off + size:]


def mangle_insert_rnd(data):
    """  在随机位置插入随机长度(长度最大为文件自身长度)的字符串 """

    length = len(data)
    # 获取要填充的数据的长度
    off = random.randint(0, length)
    size = random.randint(0, len(data))
    return insert_string(data, get_random_string(size), off)


class Mutater:
    """  随机选取变异函数，对数据进行变异 """

    def __init__(self, mutate_max_count=3, token=[], callback=None):
        """
        :param mutate_max_count: 最大变异次数，程序会从 1，mutate_max_count 选取每次的变异次数
        :param token:  用于插入一些常量到数据里面
        """

        global TOKEN

        self.mutate_max_count = mutate_max_count
        self.mutate_funcs = MANGLE_FUNCS
        self.mutate_func_count = len(MANGLE_FUNCS)
        self.callback = callback
        self.fuzz_rate = 0.001
        self.min_fuzz_size = 2
        self.max_fuzz_size = 0xffffffff

        TOKEN = token

    def mutate(self, data):
        """
        对 data 进行变异
        :param data:  待变异的数据
        :param callback: 对变异后的数据进行修正的callback 函数，比如 crc, header等
        :param fuzz_rate: 数据变异的比率， 用于决定变异的数据长度 ， len(data) * fuzz_rate
        :return:
        """

        if self.fuzz_rate == 1 or len(data) < 20:
            # 选择变异次数
            count = random.randint(1, self.mutate_max_count)
            for i in xrange(count):
                # 随机选取一个变异函数
                func = random.choice(MANGLE_FUNCS)
                data = func(data)
        else:
            length = len(data)
            fuzz_len = int(length * self.fuzz_rate)

            if fuzz_len < self.min_fuzz_size:
                fuzz_len = self.min_fuzz_size
            
            if fuzz_len > self.max_fuzz_size:
                fuzz_len = self.max_fuzz_size

            # 获取要填充的数据的长度
            off = random.randint(0, length - fuzz_len)
            pre = data[:off]
            post = data[off + fuzz_len:]
            data = data[off:off + fuzz_len]

            count = random.randint(1, self.mutate_max_count)
            for i in xrange(count):
                # 随机选取一个变异函数
                func = random.choice(MANGLE_FUNCS)
                data = func(data)
            data = pre + data + post

        if self.callback:
            data = self.callback(data)
        return data

class HonggfuzzMutater:
    __mutator_name__ = "HonggfuzzMutater"

    def __init__(self, mutate_max_count=3, token=[], callback=None):
        """
        :param mutate_max_count: 最大变异次数，程序会从 1，mutate_max_count 选取每次的变异次数
        :param token:  用于插入一些常量到数据里面
        """
        self.mutator = Mutater(mutate_max_count, token, callback)

    def mutate(self, src, dest):
        """
        对 data 进行变异
        :param data:  待变异的数据
        :param callback: 对变异后的数据进行修正的callback 函数，比如 crc, header等
        :param fuzz_rate: 数据变异的比率， 用于决定变异的数据长度 ， len(data) * fuzz_rate
        :return:
        """
        data = ""
        with open(src, "rb") as fp:
            data = fp.read()
        
        data = self.mutator.mutate(data)
        with open(dest, "wb") as fp:
            fp.write(data)


if __name__ == '__main__':

    TOKEN = ['\xde\xad\xbe\xef', '\x90\x90\x90\x90']

    src = "123456789"
    print(len(MANGLE_FUNCS))

    mutator = Mutater()

    while True:
        # print(mangle_resize(src))
        # hexdump(mangle_byte(src))
        # hexdump(mangle_bit(src))
        # hexdump(mangle_bytes(src))
        # hexdump(mangle_magic(src))
        # hexdump(mangle_incbyte(src))
        # hexdump(mangle_decbyte(src))
        # hexdump(mangle_negbyte(src))
        # hexdump(mangle_add_sub(src))
        # hexdump(mangle_mem_copy(src))
        # hexdump(mangle_mem_insert(src))
        # hexdump(mangle_memset_max(src))
        # hexdump(mangle_random(src))
        # hexdump(mangle_clonebyte(src))
        # hexdump(mangle_expand(src))
        # hexdump(mangle_shrink(src))
        # hexdump(mangle_insert_rnd(src))
        # hexdump(mangle_copy_token(src))
        # hexdump(mangle_insert_token(src))
        hexdump(mutator.mutate(src))
