#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Illustrative function that will be called by the hello bpf program
// to demonstrate BPF to BPF calls withough going through tail-calls
// This function would likely get inlined by the compiling, which would
// defeat the point of the illustration. To avoid that we explicitly
// set the noinline attribute.
static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    return ctx->args[1];
}

SEC("raw_tp")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    // call the get_opcode function
    int opcode = get_opcode(ctx);
    bpf_printk("Syscall: %d", opcode);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
