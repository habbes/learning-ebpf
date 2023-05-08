#!/usr/bin/python
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

# compile the ebpf program
b = BPF(text=program)
# The kernel implementation of the execve API depends
# on the system chip we use. b.get_syscall_fnname looks up
# the actual function name for the current machine.
syscall = b.get_syscall_fnname("execve")
print(f"System call function name {syscall}")
# We attach our program to the system call, i.e.
# The program will be loaded into the kernel
# and the hello function called whenever
# a new executable is launched
b.attach_kprobe(event=syscall, fn_name="hello")

# Read the tracing output by the kernel and print it
# trace_print90 will loop indefinitely,
# displaying trace messages. Terminate with Ctrl+C
b.trace_print()