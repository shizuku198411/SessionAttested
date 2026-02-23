//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16
#define PATH_LEN 256
#define EVT_EXEC 1
#define EVT_WORKSPACE_WRITE 2
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000

struct exec_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    __u32 flags;
    __u32 _pad;
    char  comm[COMM_LEN];
    char  filename[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline __u32 get_ppid_tgid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

static __always_inline void fill_common(struct exec_event *e) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = get_ppid_tgid();
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = 0;
    e->flags = 0;
    e->filename[0] = 0;
}

static __always_inline int is_workspace_path(const char *p) {
    if (!p) return 0;
    if (p[0] != '/') return 0;
    if (p[1] != 'w') return 0;
    if (p[2] != 'o') return 0;
    if (p[3] != 'r') return 0;
    if (p[4] != 'k') return 0;
    if (p[5] != 's') return 0;
    if (p[6] != 'p') return 0;
    if (p[7] != 'a') return 0;
    if (p[8] != 'c') return 0;
    if (p[9] != 'e') return 0;
    if (p[10] == 0 || p[10] == '/') return 1;
    return 0;
}

/* ---- (1) LSM (可能ならこれを使う) ---- */
SEC("lsm/bprm_check_security")
int on_bprm_check_security(struct linux_binprm *bprm)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->event_type = EVT_EXEC;

    const char *fn = BPF_CORE_READ(bprm, filename);
    if (fn) {
        bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---- (2) tracepoint fallback: sys_enter_execve ---- */
SEC("tracepoint/syscalls/sys_enter_execve")
int on_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->event_type = EVT_EXEC;

    const char *fn = (const char *)BPF_CORE_READ(ctx, args[0]); // filename
    if (fn) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), fn);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---- (3) tracepoint fallback: sys_enter_execveat ---- */
SEC("tracepoint/syscalls/sys_enter_execveat")
int on_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->event_type = EVT_EXEC;

    const char *fn = (const char *)BPF_CORE_READ(ctx, args[1]); // pathname
    if (fn) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), fn);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---- (4) tracepoint: sys_enter_openat (workspace write) ---- */
SEC("tracepoint/syscalls/sys_enter_openat")
int on_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 flags = BPF_CORE_READ(ctx, args[2]);
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))) {
        return 0;
    }

    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->event_type = EVT_WORKSPACE_WRITE;
    e->flags = (__u32)flags;

    const char *fn = (const char *)BPF_CORE_READ(ctx, args[1]); // filename
    if (fn) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), fn);
    }
    if (!is_workspace_path(e->filename)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
