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

Analyze the object file with `llvm-objdump -S hello.bpf.o`

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

`bytes_xlated`: How many bytes in the translated bytecode. This is the eBPF bytecode after it has passed through the verifier and possibly been modified by the kernel.
`bytes_jited`: How many bytes in the JIT-compiled machine code.


The `tag` is the SHA1 hash of the program's instructions and can be used as an idenfitier for the program.
Unlike the ID which can vary with each program load, the tag is constant. You can have multiple instances
of the same program with the same tag, but different IDs. The program can be referenced by
ID, tag, name or pinned path:

- `bpftool prog show id 540`
- `bpftool prog show name hello`
- `bpftool prog show tag d35b94b4c0c10efb`
- `bpftool prog show pinned /sys/fs/bpf/hello`


You can view a disassembly of the translated bytecode using:

```
bpftool prog dump xlated name hello
```

```
int hello(void * ctx):
; int hello(void *ctx) {
   0: (b7) r1 = 0
; bpf_printk("Hello World %d", counter);
   1: (73) *(u8 *)(r10 -2) = r1
   2: (b7) r1 = 25637
   3: (6b) *(u16 *)(r10 -4) = r1
   4: (b7) r1 = 543452274
   5: (63) *(u32 *)(r10 -8) = r1
   6: (18) r1 = 0x6f57206f6c6c6548
   8: (7b) *(u64 *)(r10 -16) = r1
   9: (18) r6 = map[id:5][0]+0
  11: (61) r3 = *(u32 *)(r6 +0)
  12: (bf) r1 = r10
; 
  13: (07) r1 += -16
; bpf_printk("Hello World %d", counter);
  14: (b7) r2 = 15
  15: (85) call bpf_trace_printk#-70832
; counter++;
  16: (61) r1 = *(u32 *)(r6 +0)
  17: (07) r1 += 1
  18: (63) *(u32 *)(r6 +0) = r1
; return XDP_PASS;
  19: (b7) r0 = 2
  20: (95) exit
```

You can also see the jited compiled code:

```
bpftool prog dump jited name hello
```

```
int hello(void * ctx):
bpf_prog_4ae0216d65106432_hello:
; int hello(void *ctx) {
   0:	nopl	(%rax,%rax)
   5:	nop
   7:	pushq	%rbp
   8:	movq	%rsp, %rbp
   b:	subq	$16, %rsp
  12:	pushq	%rbx
  13:	xorl	%edi, %edi
; bpf_printk("Hello World %d", counter);
  15:	movb	%dil, -2(%rbp)
  19:	movl	$25637, %edi
  1e:	movw	%di, -4(%rbp)
  22:	movl	$543452274, %edi
  27:	movl	%edi, -8(%rbp)
  2a:	movabsq	$8022916924116329800, %rdi
  34:	movq	%rdi, -16(%rbp)
  38:	movabsq	$-99944945115136, %rbx
  42:	movl	(%rbx), %edx
  45:	movq	%rbp, %rdi
; 
  48:	addq	$-16, %rdi
; bpf_printk("Hello World %d", counter);
  4c:	movl	$15, %esi
  51:	callq	0xfffffffff35ee854
; counter++;
  56:	movl	(%rbx), %edi
  59:	addq	$1, %rdi
  5d:	movl	%edi, (%rbx)
; return XDP_PASS;
  60:	movl	$2, %eax
  65:	popq	%rbx
  66:	leave
  67:	retq
  68:	int3

```

## Attaching to an event