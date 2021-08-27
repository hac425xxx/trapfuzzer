import struct

bb_list = []

with open("cov.bin", "rb") as fp:
    while True:
        try:
            mod_id, bb_rva = struct.unpack("<II", fp.read(8))
            bb_list.append(bb_rva)
        except Exception as e:
            # print e
            break


data = ""
for bb in bb_list:
    data += "0x{:x}\n".format(bb)

# print data

with open("log.txt", "w") as fp:
    fp.write(data)

print "0x{:x}".format(bb_list[-1])
print "0x{:x}".format(bb_list[-2])