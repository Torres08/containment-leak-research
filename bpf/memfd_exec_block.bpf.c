// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* Avoid libc errno headers in BPF builds; define EPERM locally. */
#ifndef EPERM
#define EPERM 1
#endif

#define WINDOW_NS (5ULL * 1000000000ULL)

struct event {
    __u32 pid;
    __u32 uid;
    __u64 delta_ns;
    __u64 lsm_exec_ns;   /* wall-time cost of this LSM hook invocation */
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} memfd_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int comm_is_loader(char *comm_out)
{
    char comm[16];
    int match;

    __builtin_memset(comm, 0, sizeof(comm));
    bpf_get_current_comm(&comm, sizeof(comm));

    match = (comm[0] == 'l' && comm[1] == 'o' && comm[2] == 'a' &&
             comm[3] == 'd' && comm[4] == 'e' && comm[5] == 'r' &&
             comm[6] == '\0');

    if (comm_out)
        __builtin_memcpy(comm_out, comm, sizeof(comm));

    return match;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&memfd_ts, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_exec, struct linux_binprm *bprm)
{
    __u64 hook_start = bpf_ktime_get_ns();   /* T0: hook entry */
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = hook_start;
    __u64 *ts = bpf_map_lookup_elem(&memfd_ts, &pid);
    char comm[16];

    if (!ts)
        return 0;

    if (!comm_is_loader(comm)) {
        bpf_map_delete_elem(&memfd_ts, &pid);
        return 0;
    }

    if ((now - *ts) < WINDOW_NS) {
        __u64 hook_end = bpf_ktime_get_ns();  /* T1: just before ringbuf */
        struct event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = pid;
            e->uid = (__u32)bpf_get_current_uid_gid();
            e->delta_ns   = now - *ts;
            e->lsm_exec_ns = hook_end - hook_start;
            __builtin_memcpy(e->comm, comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        bpf_map_delete_elem(&memfd_ts, &pid);
        return -EPERM;
    }

    bpf_map_delete_elem(&memfd_ts, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
