set confirm off
set pagination off
# set auto-solib-add off
# set logging file log.txt
# set logging on
set-fuzz-config fuzzmode,debug
cov-mod-info 0x400000 0x603000
set-exit-bb-list 0xC95
load-trapfuzzer-info /home/hac425/gdb-9.2/build/bb.txt
r