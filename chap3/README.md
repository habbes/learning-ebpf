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