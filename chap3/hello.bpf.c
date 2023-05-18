#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

// Define an xdp section.
// This defines that the program is an eXpress Data Path (XDP) type.
SEC("xdp")
// This function defines the eBPF program
int hello(void *ctx) {
    bpf_printk("Hello World %d", counter);
    // The eBPF program can update the global var.
    counter++;
    // XDP_PASS return value tells the kernel
    // to process the network packet normally
    return XDP_PASS;
}

// License string, crucial to eBPF programs
// Some helper functions in kernel are GPL only
// And only eBPF programs with compatible licenses
// can use such functions.
char LICENSE[] SEC("license") = "Dual BSD/GPL";
