// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#define DEFAULT_OBJ "bpf/memfd_exec_block.bpf.o"

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(unsigned int) * 2)
        return 0;

    struct event {
        unsigned int pid;
        unsigned int uid;
        unsigned long long delta_ns;
        char comm[16];
    } *e = data;

    printf("[BLOCK] pid=%u uid=%u comm=%s delta_ns=%llu\n",
           e->pid, e->uid, e->comm, e->delta_ns);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *obj_path = DEFAULT_OBJ;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link_tp = NULL;
    struct bpf_link *link_lsm = NULL;
    struct ring_buffer *rb = NULL;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    int err = 0;

    if (argc > 1)
        obj_path = argv[1];

    libbpf_set_print(libbpf_print_fn);

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "failed to increase rlimit: %s\n", strerror(errno));
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open bpf object: %s\n", obj_path);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load bpf object: %d\n", err);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "tp_memfd_create");
    if (!prog) {
        fprintf(stderr, "failed to find tracepoint program\n");
        err = 1;
        goto cleanup;
    }
    link_tp = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_memfd_create");
    if (!link_tp) {
        fprintf(stderr, "failed to attach tracepoint\n");
        err = 1;
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "block_exec");
    if (!prog) {
        fprintf(stderr, "failed to find LSM program\n");
        err = 1;
        goto cleanup;
    }
    link_lsm = bpf_program__attach_lsm(prog);
    if (!link_lsm) {
        fprintf(stderr, "failed to attach LSM program\n");
        err = 1;
        goto cleanup;
    }

    struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "failed to find events map\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("[LSM] memfd->exec block active (window=5s, comm=loader)\n");
    printf("[LSM] Ctrl+C to stop\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link_lsm);
    bpf_link__destroy(link_tp);
    bpf_object__close(obj);
    return err != 0;
}
