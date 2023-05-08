#!/usr/bin/python3
from bcc import BPF, ct

program = r"""
// macro for definining a map of type BPF_MAP_TYPE_PROG_ARRAY
// which holds an array of BPF program descriptors, with a capacity of 300 entries
BPF_PROG_ARRAY(syscall, 300);

// This program is attached to the sys_enter raw tracepoint, which gets hit
// whenever any syscall is made
// When attached to a raw tracepoint, the program gets a context arg of type bpf_raw_tracepoint_args
int hello(struct bpf_raw_tracepoint_args *ctx)
{
    // the opcode argument identifies which syscall is being made
    int opcode = ctx->args[1];
    // the following method call is rewritten by BCC as:
    // bpf_tail_call(ctx, syscall, opcode)
    syscall.call(ctx, opcode);
    // If the tail call succeeds, the current bpf program
    // is replaced by the callee on the stack (similar to how an OS fork works)
    // That means the following statement will only be reached if the tail call failed
    // (e.g. if the specified opcode was not in the map)
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

// This program will be loaded into the syscall map to be
// executed as a tail call when execve's opcode is matched in hello()
int hello_execve(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

// Will be loaded into the syscall map and will be referred to
// by more than one entry in the array
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    if (ctx->args[1] == 222) {
        bpf_trace_printk("Creating a timer");
    } else if (ctx->args[1] == 226) {
        bpf_trace_printk("Deleting a timer");
    } else {
        bpf_trace_printk("Some other timer operation");
    }

    return 0;
}

// Does nothing, for syscalls where we don't want to trace anything
int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# load_func returns a file descriptor for the program
# Note that the tail call needs to have the same program type
# as the parent (raw tracepoint)
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")
# ct.c_int converts Python ints to C ints
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# Ignore some syscalls that come up a lot
to_ignore = set(range(300)) - set([59, 222, 224, 225, 226])
for call in to_ignore:
    prog_array[ct.c_int(call)] = ct.c_int(ignore_fn.fd)

b.trace_print()