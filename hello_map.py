#!/usr/bin/python
from bcc import BPF
from time import sleep

program = r"""
// BCC macro to create a hash table map
BPF_HASH(counter_table);

int count_by_uid(void *ctx)
{
    u64 uid;
    u64 counter = 0;
    u64 *p_value;

    // bpf_get_current_uid_gid() is a helper for getting
    // the current user ID. It returns both the user
    // and group ID. The user ID is in the lower 32 bits.
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // BCC lets use convenient syntax like method calls
    // that do not exist in C proper
    // lookups find the value with key uid and
    // returns a pointer to the value
    p_value = counter_table.lookup(&uid);

    if (p_value != 0) {
        counter = *p_value;
    }
    counter++;
    counter_table.update(&uid, &counter);

    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="count_by_uid")
syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall, fn_name="count_by_uid")
syscall = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall, fn_name="count_by_uid")

while True:
    sleep(2)
    s = ""
    # BCC creates a python object to represent the hash table
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)