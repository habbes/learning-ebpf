#!/usr/bin/python
from bcc import BPF

# This program prints the message "Hello World"
# whenever the execve syscall is called. It also prints
# some information about the process that triggered the call
program = r"""
// Create a map (ring buffer) that will be used to pass messages
// from kernel to user space
BPF_PERF_OUTPUT(output);

struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int log_process_data(void *ctx)
{
    struct data_t data = {};
    char message[12] = "Hello World";

    // bpf_get_current_pid_tgid returns a 64bit val representing the ID of the process
    // that triggered this eBPF program to run.
    // The process ID is in the top 32 bits
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // helper function for getting the name of the executable/command
    // that's running the process that made the execve syscall
    bpf_get_current_comm(&data.command, sizeof(data.command));
    // Reads data from kernel space (message) into the destination &data.message
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    // put the data in the map
    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="log_process_data")

# Callback that's called whenever data is read from the ring buffer
def print_event(cpu, data, size):
    # Grab data from the output map
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} " + \
          f"{data.message.decode()}")

# opens the perf ring buffer for reading
b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()