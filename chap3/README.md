# Compiling eBPF programs

An eBPF source code needs to be compiled into the machine instructions that the eBPF virtual machine can understand: eBPF bytecode.
The Clang compiler from the LLVM project will do this if you specify -target bpf.
The following is an extract from a Makefile that will do the compilation:

```Makefile
hello.bpf.o: %.o: %.c
   clang \
       -target bpf \
       -I/usr/include/$(shell uname -m)-linux-gnu \
       -g \
       -O2 -c $< -o $@
```

This generates an object file called hello.bpf.o from the source code in hello.bpf.c. The -g flag is optional here,3 but it generates debug information so that you can see the source code alongside the bytecode when you inspect the object file. Let’s inspect this object file to better understand the eBPF code it contains.


Compile the code with `make hello`

This should generate a `hello.bpf.o` object file.

Analyze the object file with `llvm-objdump hello.bpf.o`

Load the program in the kernel using `bpftool`:
- `bpftool prog load hello.bpf.o /sys/fs/bpf/hello`
- The program will be pinned at `/sys/fs/bpf/hello`
- Confirm that it has been loaded using `ls /sys/fs/bpf/hello`

Display a list of eBPF programs using `bpftool prog list`.
Find the entry called `hello`:

```
422: xdp  name hello  tag 4ae0216d65106432  gpl
        loaded_at 2023-06-02T20:22:51+0300  uid 0
        xlated 168B  jited 105B  memlock 4096B  map_ids 8,9
        btf_id 99
```
In this case the id is 422, knowing the id we can get more information about the program using

```
bpftool prog show id 422 --pretty
```

```
$ bpftool prog show id 540 --pretty
{
    "id": 540,
    "type": "xdp",
    "name": "hello",
    "tag": "d35b94b4c0c10efb",
    "gpl_compatible": true,
    "loaded_at": 1659461987,
    "uid": 0,
    "bytes_xlated": 96,
    "jited": true,
    "bytes_jited": 148,
    "bytes_memlock": 4096,
    "map_ids": [165,166
    ],
    "btf_id": 254
}
```