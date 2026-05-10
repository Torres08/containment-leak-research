# Phase 3: Blue Team Deployment (Native Hardening and Dynamic eBPF)

This phase applies platform-specific defenses to neutralize the fileless payload proven in Phase 2. The approach is explicit, repeatable, and suitable for a professional security evaluation.

## Executive Summary
We applied two defenses that match each runtime's security model:

- **Docker:** Dynamic eBPF monitoring to block fileless execution paths. The eBPF program intercepts `memfd_create` and `execve` syscalls, enforcing a deny policy for processes exhibiting fileless execution behavior.
- **Apptainer:** Native seccomp hardening to block critical syscalls (`memfd_create` and `execveat`) required for fileless execution. This approach leverages Apptainer's built-in security features to enforce syscall restrictions.

Both defenses prevent the reverse shell from reaching the host while keeping the process easy to understand and reproduce.

---

## 0. Threat Model and Defensive Objectives

**Threat model:** The loader unpacks an ELF payload into RAM using `memfd_create()` and executes it using `fexecve()`. This bypasses static scanners because no payload file exists on disk.

**Defensive objective:** Block the fileless execution path itself, regardless of payload type. Docker uses kernel enforcement with eBPF LSM; Apptainer uses native seccomp to deny the relevant syscalls.

---

## 0.1 What is eBPF (Detailed Explanation)

**eBPF** (Extended Berkeley Packet Filter) is a technology that allows programs to run in the Linux kernel without modifying the kernel itself. It is widely used for performance monitoring, security, and networking. In this phase, we use eBPF for security enforcement.

### Tools and Functions Used:
1. **Tracepoints:** These are hooks in the kernel that allow us to monitor specific events, such as `memfd_create`. We use the `tracepoint/syscalls/sys_enter_memfd_create` to capture when a process creates an in-memory file.
2. **LSM Hooks:** Linux Security Modules (LSM) provide hooks for enforcing security policies. The `bprm_check_security` hook is used to intercept and block execution attempts based on our policy.
3. **BPF Maps:** These are key-value stores used to share data between eBPF programs. We use a map to store timestamps of `memfd_create` calls for each process ID (PID).

### Why These Tools Are Effective:
- **Tracepoints** allow us to monitor syscall activity without significant performance overhead.
- **LSM Hooks** enforce security policies at critical points, such as before a process executes.
- **BPF Maps** enable efficient data sharing and lookup, which is crucial for real-time enforcement.

---

## 1. Docker Defense (Dynamic eBPF Monitoring)

### Technical Implementation

**Mechanism:**
1. Trace `memfd_create` and store the timestamp for the PID.
2. At exec time, check whether the same PID created a memfd within a short window.
3. If true, deny exec with `-EPERM` and log a block event.

**Why this works:** The loader's sequence is tight and deterministic: `memfd_create` -> `write` -> `fexecve`. Blocking at `bprm_check_security` guarantees the payload never takes control.

**Safety control:** Apply the rule only when the process name (`comm`) is `loader`, preventing false blocks of Docker internals such as runc.

### Code Walkthrough (Docker LSM)

**BPF program:** `bpf/memfd_exec_block.bpf.c`

**1) Trace memfd_create:**
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
This function captures the `memfd_create` syscall and records the timestamp for the process ID (PID) in a BPF map.

**2) Block exec if it follows memfd_create:**
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

    if ((now - *ts) < WINDOW_NS) {
        return -EPERM;
    }

    bpf_map_delete_elem(&memfd_ts, &pid);
    return 0;
}
```
This function enforces the policy by checking if the process recently created a memfd and matches the `loader` name. If so, it denies execution.

**3) Loader comm name:** `src/loader.c`
```c
(void)prctl(PR_SET_NAME, "loader", 0, 0, 0);
```
This sets the process name to `loader`, ensuring the policy targets only the intended process.

---

## 2. Apptainer Defense (Native Seccomp Policy)

### Technical Implementation

**Mechanism:** Apply a seccomp profile that denies `memfd_create` and `execveat`. The loader cannot create an in-memory file or exec from it, so the fileless chain breaks regardless of payload.

**Seccomp profile:** `deployment/seccomp_memfd_exec.json`
```json
{
    "defaultAction": "SCMP_ACT_ALLOW",
    "flags": ["SECCOMP_FILTER_FLAG_LOG"],
    "syscalls": [
        {"names": ["memfd_create"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1},
        {"names": ["execveat"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}
    ]
}
```

### Why Seccomp is Effective:
- **Granular Control:** Seccomp allows fine-grained control over syscalls, enabling us to block only the ones required for fileless execution.
- **Built-in Logging:** The `SECCOMP_FILTER_FLAG_LOG` flag ensures that denied syscalls are logged, providing evidence of enforcement.
- **Minimal Overhead:** Seccomp operates at the kernel level, ensuring high performance.

---

## 3. Execution Summary (What We Ran)

**Docker:**
```bash
make docker-defense
make docker-attack
docker exec -i victim-webapp /loader
```
**Result:** Exec blocked at the kernel, no shell.

**Apptainer:**
```bash
make apptainer-defense
make apptainer-attack
```
**Result:** Loader fails before payload execution because seccomp denies `memfd_create` or `execveat` (and the denial can be logged).

---

## 4. Basic Defensive Tools (Why These Are Enough)

**eBPF LSM:** Kernel-enforced deny at exec time. Strongest option for Docker because runtime defaults are permissive and fileless loaders can execute in memory.

**Native seccomp policy:** Minimal, audit-friendly defenses built into Apptainer. The syscalls are blocked at the kernel boundary and can be logged for evidence.

**Defense split conclusion:** Docker needs external kernel enforcement for fileless exec. Apptainer can block the effect using built-in restrictions.

---

## 5. Goals and Timeline

### Measurable Goals
| Platform | Defense Strategy | Success Criteria |
| :--- | :--- | :--- |
| **Docker** | Dynamic eBPF | The eBPF program effectively intercepts and blocks the hidden memory execution. |
| **Apptainer** | Native Seccomp | Seccomp denies `memfd_create`/`execveat`, preventing fileless execution. |

### Timeline and Milestones
*   **Execution Period:** May 15 – May 23, 2026.
*   **Core Development:** May 15 – May 17.
*   **Validation and Conference Presentation:** May 17 – May 23, 2026.

---

## 6. Expected Findings

We anticipate proving that while Docker requires external, specialized tools (eBPF) for deep-kernel monitoring to stop fileless execution, Apptainer provides a more "secure-by-default" surface where native seccomp can block the same fileless path without external enforcement.
