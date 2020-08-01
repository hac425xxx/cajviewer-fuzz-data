# cajviewer-fuzz-data

AFL QEMU Fuzz测试

```
export AFL_CODE_START=0x4001710880
export AFL_CODE_END=0x4001c4584f
export AFL_ENTRYPOINT=0x4000000b71
/home/hac425/AFLplusplus-2.66c/afl-fuzz -m none -Q -t 20000 -i - -o out -- ./test_CAJFILE_OpenEx1 @@
```
