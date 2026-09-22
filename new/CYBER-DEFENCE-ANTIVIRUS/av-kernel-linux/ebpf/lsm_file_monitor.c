// av-kernel-linux/ebpf/lsm_file_monitor.c
// BPF LSM program for real-time file access monitoring
// Compiled to BPF bytecode and loaded via libbpf in av-service
// Requires: Linux 5.8+ with CONFIG_BPF_LSM=y

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 256
#define RING_BUF_SIZE 256  // Pages
#define SCAN_DEDUP_WINDOW_NS 60000000000ULL

// Event structure - sent to userspace via ring buffer
struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u32 flags;        // open flags (O_RDONLY, O_WRONLY, etc.)
    __u32 mode;         // file mode (permissions)
    __u8 operation;     // 1=open, 2=execute, 3=write
    __u8 verdict;       // 0=allow (default), 1=block
    char filename[MAX_FILENAME_LEN];
};

// Ring buffer for event delivery to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUF_SIZE * 4096);  // RING_BUF_SIZE pages
} file_events SEC(".maps");

// Statistics map - track operations
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} statistics SEC(".maps");

// Blocked PIDs set (optional - PIDs to monitor specifically)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} target_pids SEC(".maps");

// Dedup cache to avoid re-scanning hot files repeatedly.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);   // inode
    __type(value, __u64); // last scan timestamp (ns)
    __uint(max_entries, 10000);
} recent_scans SEC(".maps");

// Helper: Extract filename from inode
static __always_inline int get_filename(struct dentry *dentry, char *buf, size_t size) {
    struct dentry *parent = NULL;
    struct qstr d_name = {};
    unsigned int len = 0;
    int i;

    // Safely dereference dentry
    #pragma clang loop unroll(disable)
    for (i = 0; i < 4; i++) {
        if (!dentry) break;
        
        // Read d_name from dentry
        bpf_probe_read_kernel_str(&d_name, sizeof(d_name), &dentry->d_name);
        
        if (d_name.len > 0 && d_name.len < size) {
            bpf_probe_read_kernel_str(buf + len, size - len, d_name.name);
            len += d_name.len;
            
            if (len < size - 1) {
                buf[len++] = '/';
            }
        }
        
        // Move to parent
        bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
        dentry = parent;
    }

    if (len > 0 && len < size) {
        buf[len] = '\0';
    }

    return len;
}

static __always_inline bool has_ext(const char *path, const char *ext) {
    int i = 0;
    int ext_len = 0;

    #pragma clang loop unroll(full)
    for (int j = 0; j < 16; j++) {
        if (ext[j] == '\0') {
            ext_len = j;
            break;
        }
    }
    if (ext_len == 0) {
        return false;
    }

    #pragma clang loop unroll(disable)
    for (i = 0; i < MAX_FILENAME_LEN - 1; i++) {
        if (path[i] == '\0') {
            break;
        }
    }
    if (i < ext_len) {
        return false;
    }

    int start = i - ext_len;
    #pragma clang loop unroll(disable)
    for (int k = 0; k < 16; k++) {
        if (k >= ext_len) {
            break;
        }
        if (path[start + k] != ext[k]) {
            return false;
        }
    }
    return true;
}

static __always_inline bool contains_token(const char *path, const char *needle, int needle_len) {
    if (needle_len <= 0) {
        return false;
    }

    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_FILENAME_LEN - 1; i++) {
        if (path[i] == '\0') {
            break;
        }

        bool matched = true;
        #pragma clang loop unroll(disable)
        for (int j = 0; j < 32; j++) {
            if (j >= needle_len) {
                break;
            }
            if (i + j >= MAX_FILENAME_LEN - 1 || path[i + j] == '\0' || path[i + j] != needle[j]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return true;
        }
    }
    return false;
}

static __always_inline bool should_scan_path(const char *path, __u32 mode) {
    // Skip common virtual/system paths.
    if (contains_token(path, "proc/", 5) ||
        contains_token(path, "sys/", 4) ||
        contains_token(path, "dev/", 4)) {
        return false;
    }

    // Skip noisy transient paths/files.
    if (contains_token(path, "/tmp/", 5) ||
        contains_token(path, ".tmp", 4) ||
        contains_token(path, "/.cache/", 8) ||
        contains_token(path, "/cache/", 7) ||
        has_ext(path, ".log")) {
        return false;
    }

    // Always scan executable modes.
    if (mode & 0111) {
        return true;
    }

    if (contains_token(path, "Downloads", 9) || contains_token(path, "downloads", 9)) {
        return true;
    }

    // Executables and libraries.
    if (has_ext(path, ".exe") || has_ext(path, ".dll") || has_ext(path, ".so") ||
        has_ext(path, ".dylib") || has_ext(path, ".app") || has_ext(path, ".bin")) {
        return true;
    }

    // Scripts.
    if (has_ext(path, ".sh") || has_ext(path, ".bat") || has_ext(path, ".cmd") ||
        has_ext(path, ".ps1") || has_ext(path, ".py") || has_ext(path, ".rb")) {
        return true;
    }

    // Archives/documents.
    if (has_ext(path, ".zip") || has_ext(path, ".rar") || has_ext(path, ".7z") ||
        has_ext(path, ".tar") || has_ext(path, ".doc") || has_ext(path, ".xls") ||
        has_ext(path, ".ppt") || has_ext(path, ".pdf")) {
        return true;
    }

    return false;
}

// Helper: Update statistics counter
static __always_inline void update_stats(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&statistics, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&statistics, &key, &initial, 0);
    }
}

// LSM hook: file_open
// Called whenever a file is opened
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret) {
    if (ret != 0 || !file) {
        return 0;
    }

    __u32 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;

    __u32 flags = 0;
    __u32 mode = 0;
    struct dentry *dentry = NULL;
    struct inode *inode = NULL;
    bpf_probe_read_kernel(&flags, sizeof(flags), &file->f_flags);
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (inode) {
        bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
    }
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);

    char path[MAX_FILENAME_LEN] = {};
    if (!dentry) {
        return 0;
    }
    get_filename(dentry, path, MAX_FILENAME_LEN);

    if (!should_scan_path(path, mode)) {
        return 0;
    }

    // Rate limit by inode.
    __u64 now = bpf_ktime_get_ns();
    __u64 ino = 0;
    if (inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
    }
    if (ino != 0) {
        __u64 *last_scan = bpf_map_lookup_elem(&recent_scans, &ino);
        if (last_scan && (now - *last_scan) < SCAN_DEDUP_WINDOW_NS) {
            return 0;
        }
        bpf_map_update_elem(&recent_scans, &ino, &now, BPF_ANY);
    }

    // Allocate event structure only after filters/dedupe.
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        update_stats(0);  // ring buffer full
        return 0;
    }

    // Fill event data.
    event->pid = pid;
    event->uid = uid;
    event->gid = gid;
    event->timestamp = now;
    event->operation = 1;  // file_open
    event->verdict = 0;    // allow (default)
    event->flags = flags;
    event->mode = mode;
    bpf_probe_read_kernel_str(event->filename, MAX_FILENAME_LEN, path);

    bpf_ringbuf_submit(event, 0);
    update_stats(1);  // events submitted

    // Always allow kernel file operations.
    return 0;
}

// LSM hook: inode_unlink
// Called when a file is deleted
SEC("lsm/inode_unlink")
int BPF_PROG(lsm_inode_unlink, struct inode *dir, struct dentry *dentry, int ret) {
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->operation = 3;  // write/delete
    event->verdict = 0;

    if (dentry) {
        get_filename(dentry, event->filename, MAX_FILENAME_LEN);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// LSM hook: bprm_check_security
// Called when a program is executed
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm, int ret) {
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->operation = 2;  // execute
    event->verdict = 0;

    // Get filename from bprm->filename
    if (bprm) {
        bpf_probe_read_kernel_str(event->filename, MAX_FILENAME_LEN, bprm->filename);
    }

    bpf_ringbuf_submit(event, 0);
    update_stats(2);  // Stats key 2: executions tracked
    
    return 0;
}

// Statistics helper: read counter
// Called from userspace to get statistics
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask, int ret) {
    // This is a minimal LSM hook just to satisfy module loading
    // Real filtering happens in file_open above
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
