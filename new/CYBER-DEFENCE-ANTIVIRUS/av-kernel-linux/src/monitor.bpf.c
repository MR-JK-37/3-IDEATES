// SPDX-License-Identifier: GPL-2.0
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define AF_INET 2

#define AV_SCHEMA_VERSION 2
#define EVENT_FILE_ACCESS 1
#define EVENT_PROCESS_EXEC 2
#define EVENT_NET_CONNECT 3
#define ACTION_BLOCK 1
#define ACTION_QUARANTINE 2

struct av_event {
    __u16 schema_version;
    __u16 event_kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u32 open_flags;
    __u32 write_intent;
    __u64 inode;
    char comm[16];
    char path[256];
    __u32 remote_ip;
    __u16 remote_port;
    __u16 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct av_enforce_value {
    __u8 action;
    __u8 reserved[7];
    __u64 expires_at_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct av_enforce_value);
} enforce_pid_actions SEC(".maps");

static __always_inline int enforce_for_current_pid(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct av_enforce_value *value = bpf_map_lookup_elem(&enforce_pid_actions, &pid);
    __u64 now;

    if (!value)
        return 0;

    now = bpf_ktime_get_ns();
    if (value->expires_at_ns <= now) {
        bpf_map_delete_elem(&enforce_pid_actions, &pid);
        return 0;
    }

    if (value->action == ACTION_BLOCK || value->action == ACTION_QUARANTINE)
        return -13; // -EACCES

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, void *file, int ret)
{
    if (ret != 0)
        return ret;
    return enforce_for_current_pid();
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm_check, void *bprm, int ret)
{
    if (ret != 0)
        return ret;
    return enforce_for_current_pid();
}

SEC("tracepoint/syscalls/sys_enter_execve")
int hook_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct av_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->schema_version = AV_SCHEMA_VERSION;
    e->event_kind = EVENT_PROCESS_EXEC;
    e->pid = pid_tgid >> 32;
    e->tgid = (__u32)pid_tgid;
    e->uid = uid_gid & 0xffffffff;
    e->gid = uid_gid >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int hook_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct av_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 flags = (__u32)ctx->args[2];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    if (bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[1]) <= 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->schema_version = AV_SCHEMA_VERSION;
    e->event_kind = EVENT_FILE_ACCESS;
    e->pid = pid_tgid >> 32;
    e->tgid = (__u32)pid_tgid;
    e->uid = uid_gid & 0xffffffff;
    e->gid = uid_gid >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->open_flags = flags;
    e->write_intent = !!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int hook_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in sa = {};
    struct av_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    if (sa.sin_family != AF_INET)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->schema_version = AV_SCHEMA_VERSION;
    e->event_kind = EVENT_NET_CONNECT;
    e->pid = pid_tgid >> 32;
    e->tgid = (__u32)pid_tgid;
    e->uid = uid_gid & 0xffffffff;
    e->gid = uid_gid >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->remote_ip = sa.sin_addr.s_addr;
    e->remote_port = __builtin_bswap16(sa.sin_port);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
