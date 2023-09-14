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

The program type has to match the type of event it's being attached to. Here's an example
attaching out XDP program to an XDP event on a network interface:

```
bpftool net attach xdp id 540 dev eth0
```

PS: to list network interfaces and their details, you can use the `ip addr` or `ip link show` commands.

You can view all network-attached eBPF programs using:

```
bpftool net list
```

```
xdp:
ens33(2) generic id 49

tc:

flow_dissector:

netfilter:
```

The program with id 49 is attached to the XDP event on the `ens33` interface.

You can also inspect the network interface using `ip link`. The output looks like:

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:ed:5f:c8 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 49 tag 4ae0216d65106432 jited 
    altname enp2s1
```

In this example `lo` is the loopback interface (localhost) and `ens33` is used to connect to the outside world.
`ens33` has a JIT-compiled eBPF program with id 49 and tag `4ae0216d65106432` attached to its XDP hook. You can also use
`ip link` to attach and detach XDP programs.


Now we should be able to see trace output from the `hello` program every time a network packet is received:

```
cat /sys/kernel/debug/tracing/trace_pipe
```

If you can't remember the location of the trace pipe, you can use the command: `bpftool prog tracelog`


Output looks like:

```
ksoftirqd/1-23      [001] d.s21  2970.826738: bpf_trace_printk: Hello World 1039
ksoftirqd/1-23      [001] d.s21  2970.826918: bpf_trace_printk: Hello World 1040
ksoftirqd/1-23      [001] d.s21  2970.827034: bpf_trace_printk: Hello World 1041
    <idle>-0       [001] d.s31  2971.107402: bpf_trace_printk: Hello World 1042
    <idle>-0       [001] d.s31  2971.387727: bpf_trace_printk: Hello World 1043
    <idle>-0       [001] d.s31  2971.388720: bpf_trace_printk: Hello World 1044
    <idle>-0       [001] d.s31  2971.390576: bpf_trace_printk: Hello World 1045
```

We see `<idle>-0` instead of a process id associated with these events because these events
were not triggered by a process. The XDP event results from the arrival of a network packet,
at that point the system hasn't done anything with the packet other than receive it in memory,
and it has no idea what the packet is or where it's going.


## Global Variables

eBPF maps can be accessed from an eBPF and user space. Multiple runs of an eBPF program
can access the same map instance. This makes it ideal for global state. As a result,
map semantics are used to support features like global variables.

Behind the scenes, a global variable like `counter` in our sample program is stored
as a map entry.

To list eBPF maps, use the command:

```
bpftool map list
```

```
165: array  name hello.bss  flags 0x400
        key 4B  value 4B  max_entries 1  memlock 4096B
        btf_id 254
166: array  name hello.rodata  flags 0x80
        key 4B  value 15B  max_entries 1  memlock 4096B
        btf_id 254  frozen
```

A bss section in a object file from a C program typically holds global variables.
You can see its content using

```
bpftool map dump name hello.bss
```
You can also use the id: `bpftool map dump id 165`

```
[{
        "value": {
            ".bss": [{
                    "counter": 11127
                }
            ]
        }
    }
]
```

This type of pretty-printed output that shows the contents of the map including key names is
possible only if BTF-information is available, i.e. program was compiled with the `-g` flag.
If you omit the flag, the output would look more like:

```
key: 00 00 00 00  value: 19 01 00 00
Found 1 element
```

We can't tell the variable name in this case, but can infer that we have one entry
with the value `19 01 00 00` which is `281` in decimal (little-endian).

Maps are also used to hold static data, like string literals.

```
bpftool map dump id 166
```

```
[{
        "value": {
            ".rodata": [{
                    "hello.____fmt": "Hello World %d"
                }
            ]
        }
    }
]
```

Of, if you didn't use the `-g` flag:

```
key: 00 00 00 00  value: 48 65 6c 6c 6f 20 57 6f  72 6c 64 20 25 64 00
Found 1 element
```

The value is the ASCII representaton of the string `"Hello World %d"`.

## Detaching the Program

To detach the program from the network interface:

```
bpftool net detach xdp dev ens33
```

Then run the following command to verify that the program has been detached:

```
bpftool net list
```

## Unloading the program

To unload the program, delete the pinned pseudofile:

```
rm /sys/fs/bpf/hello
```

Then run the following command to ensure the program is unloaded:
```
bpftool prog show name hello
```

## BPF to BPF calls

Besides tail calls (where we add BPF program descriptors in a map to be able to call them from
other BPF programs), you can also make BPF to BPF calls by calling functions from a BPF program.

This is demonstrated in the `hello-func.bpf.c` code where the `hello` program (which is attached
to a raw tracepoint) calls the `get_opcode` function.

Compile the program:

```
make
```

Load it:
```
bpftool prog load hello-func.bpf.o /sys/fs/bpf/hello
```
```
bpftool prog list name hello
```

```
150: raw_tracepoint  name hello  tag c86c2cef74f2057a  gpl
        loaded_at 2023-09-14T08:39:08+0300  uid 0
        xlated 120B  jited 88B  memlock 4096B  map_ids 5
        btf_id 96
root@habbes-ubuntu-v
```

Inspect the eBPF bytecode to see the `get_opcode` function

```
bpftool prog dump xlated name hello
```

```
int hello(struct bpf_raw_tracepoint_args * ctx):
; int opcode = get_opcode(ctx);
   0: (85) call pc+12#bpf_prog_cbacc90865b1b9a5_get_opcode
   1: (b7) r1 = 6563104
; bpf_printk("Syscall: %d", opcode);
   2: (63) *(u32 *)(r10 -8) = r1
   3: (18) r1 = 0x3a6c6c6163737953
   5: (7b) *(u64 *)(r10 -16) = r1
   6: (bf) r1 = r10
; 
   7: (07) r1 += -16
; bpf_printk("Syscall: %d", opcode);
   8: (b7) r2 = 12
   9: (bf) r3 = r0
  10: (85) call bpf_trace_printk#-90784
; return 0;
  11: (b7) r0 = 0
  12: (95) exit
int get_opcode(struct bpf_raw_tracepoint_args * ctx):
; return ctx->args[1];
  13: (79) r0 = *(u64 *)(r1 +8)
; return ctx->args[1];
  14: (95) exit
```

The function call instruction (`0x85`) requires putting the current state on the
eBPF VM stack so that when the called function exists, execution can continue in the
caller. Since the stack size is limited to 512 bytes, BPF to BPF calls can't be very deeply nested.