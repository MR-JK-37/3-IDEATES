/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * av_monitor.bpf.c
 * Minimal eBPF PoC: observe file open events and emit an event to userspace via ring buffer.
 * NOTE: This is a minimal, defensive PoC. It does NOT implement blocking logic.
 * Build with clang -O2 -target bpf
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event_t {
    __u32 pid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    struct event_t *e;
    const char *name = NULL;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Note: reading kernel pointers is version-dependent. This PoC tries to read a dentry name.
     * A production loader should use CO-RE helpers and robust field access. */
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (void *)file->f_path.dentry->d_name.name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
