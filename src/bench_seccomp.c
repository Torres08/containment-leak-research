/*
 * bench_seccomp.c — Microbenchmark for memfd_create syscall latency
 * Measures baseline cost vs. Seccomp-filtered cost.
 *
 * Usage:
 *   Baseline:  ./bench_seccomp
 *   In Apptainer with seccomp profile: will fail on first call (EPERM)
 *   So we measure the rejection cost instead.
 *
 * Compile: gcc -O2 -o bench_seccomp bench_seccomp.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/memfd.h>

#define ITERATIONS 100000

static inline uint64_t get_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    uint64_t start, end, total = 0;
    uint64_t min_ns = UINT64_MAX, max_ns = 0;
    int fd;
    int actual_iters = 0;
    int seccomp_hit = 0;

    printf("bench_seccomp: measuring memfd_create() latency over %d iterations\n", ITERATIONS);
    printf("Environment: %s\n\n", getenv("APPTAINER_NAME") ? "Apptainer (Seccomp active)" : "Baseline (no Seccomp)");

    for (int i = 0; i < ITERATIONS; i++) {
        start = get_ns();
        fd = (int)syscall(SYS_memfd_create, "bench", 0);
        end = get_ns();

        uint64_t elapsed = end - start;

        if (fd < 0) {
            if (errno == EPERM) {
                /* Seccomp is active — measure rejection latency */
                total += elapsed;
                actual_iters++;
                seccomp_hit = 1;
                if (elapsed < min_ns) min_ns = elapsed;
                if (elapsed > max_ns) max_ns = elapsed;
                continue;
            }
            /* Other error — skip */
            continue;
        }

        /* Baseline: fd opened, measure and close */
        total += elapsed;
        actual_iters++;
        if (elapsed < min_ns) min_ns = elapsed;
        if (elapsed > max_ns) max_ns = elapsed;
        close(fd);
    }

    if (actual_iters == 0) {
        fprintf(stderr, "No measurements recorded.\n");
        return 1;
    }

    double avg = (double)total / (double)actual_iters;

    printf("=== RESULTS ===\n");
    printf("Mode            : %s\n", seccomp_hit ? "SECCOMP REJECTION" : "BASELINE (no Seccomp)");
    printf("Iterations      : %d\n", actual_iters);
    printf("Total time (ns) : %lu\n", total);
    printf("Average (ns)    : %.2f\n", avg);
    printf("Min (ns)        : %lu\n", min_ns);
    printf("Max (ns)        : %lu\n", max_ns);

    return 0;
}
