from idautils import *
from idaapi import *
import idc
import os
from struct import pack, unpack
import sys


# Wait for analysis to end
idc.auto_wait()

filename = idaapi.get_root_filename()
base = idaapi.get_imagebase()
allBlocks = {}
BBcount = 0
Fcount = 0
break_instr_size = 1

file = open("{}-bb.txt".format(filename), 'wb')


base = idaapi.get_imagebase()
lastEA = base
for segment_ea in Segments():
    segment = idaapi.getseg(segment_ea)
    if segment.end_ea > lastEA:
        lastEA = segment.end_ea

# first write rva size
file.write(struct.pack("<I", lastEA - base))


data = pack("<I", len(filename)+1)
if sys.version_info >= (3, 0):
    data += filename.encode()
    data += b"\x00"
else:
    data += filename
    data += "\x00"
file.write(data)
for segment_ea in Segments():
    segment = idaapi.getseg(segment_ea)
    if segment.perm & idaapi.SEGPERM_EXEC == 0:
        continue

    for location in Functions(segment.start_ea, segment.end_ea):
        Fcount += 1
        blocks = idaapi.FlowChart(idaapi.get_func(location))
        for block in blocks:
            BBcount += 1
            if block.start_ea not in allBlocks:
                if idc.print_insn_mnem(block.start_ea) == "":
                    print("Skipping %08X because this is not code" % (block.start_ea))
                    print("    " + GetDisasm(block.start_ea))
                    break

                voff = block.start_ea - base
                foff = idaapi.get_fileregion_offset(block.start_ea)
                instr = idaapi.get_bytes(block.start_ea, break_instr_size)

                if foff == -1:
                    continue

                data = pack("<III", voff, foff, break_instr_size)
                data += instr
                file.write(data)
                allBlocks[block.start_ea] = True
file.close()
print("Discovered %d basic blocks in %d functions" % (BBcount, Fcount))


idc.qexit(0)
