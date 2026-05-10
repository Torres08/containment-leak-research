# Phase 2 Deep-Dive: Fileless Execution and Memory-Resident Exploitation

**Context:** Research on Methods for Application Containment — Vilnius University MICAC  
**Author:** Juan Luis Torres Ramos | **Supervisor:** Assoc. Prof. Linas Bukauskas  
**Subject:** Offensive Research & Evasion (Fileless Malware & Page Cache Poisoning)

---

## 1. Executive Summary: The Offensive Objective
Phase 2 demonstrated that container isolation is effectively "transparent" to memory-resident threats. We implemented a multi-stage attack chain that bypasses static filesystem scanners by operating exclusively in anonymous RAM. The research proved that without dynamic kernel-level monitoring (Phase 3), fileless execution and container escapes can remain entirely undetected by traditional security tooling.

---

## 2. Architectural Component: The Fileless Loader (`loader.c`)
The loader's primary goal is to execute a payload without creating a filesystem inode.

### 2.1 The XOR Obfuscation Layer (Static Evasion)
To bypass the "ELF Magic Number" detection (`\x7fELF`) used by scanners like `file` and `strings`, we apply a single-byte XOR transformation at build-time.
*   **Technique:** `byte ^ 0xAB`
*   **Result:** The payload becomes a blob of high-entropy data. The loader reverses this in-memory before execution.
*   **Forensic Impact:** Static analysis of the container image reveals a "benign" loader binary with a large data table, but no second executable.

### 2.2 Anonymous Memory Mapping (`memfd_create`)
The core of the fileless chain is the `memfd_create()` syscall (introduced in Kernel 3.17).
*   **Logic:** It creates an anonymous file backed by `tmpfs` but with no entry in the directory tree.
*   **Hardening Flags:**
    *   `MFD_CLOEXEC`: Ensures the file descriptor is not leaked to child processes.
    *   `MFD_ALLOW_SEALING`: Enables the use of `fcntl(F_ADD_SEALS)` to make the payload immutable in RAM.
*   **Forensic Signature:** Reading `/proc/self/exe` shows a broken link or a path starting with `/memfd: (deleted)`, a definitive indicator of fileless execution.

---

## 3. Exploit Theory: CVE-2026-31431 (Copy Fail)
We researched the weaponization of a Page Cache poisoning primitive to bridge the container-to-host boundary.

### 3.1 The AF_ALG Primitive
The attack leverages the Linux Kernel Crypto API (`AF_ALG`).
1. **The Setup:** The attacker binds an `AF_ALG` socket to a vulnerable AEAD template (e.g., `authencesn`).
2. **The Collision:** Using `splice()`, the attacker moves a reference of a read-only host file's page (e.g., `/mnt/target_script`) into the kernel's cryptographic input buffer.
3. **The Corruption:** By providing an undersized output buffer, the AEAD engine's "In-Place" optimization triggers a 4-byte out-of-bounds write into the Page Cache of the *original host file*.

### 3.2 Result: Escape Chain Neutralization
On our research kernel (6.12.74), the exploit was neutralized at the `setsockopt(ALG_SET_KEY)` stage.
*   **Reason:** The Debian kernel effectively implements API-level policy enforcement, refusing to instantiate the specific key format required by the vulnerable template.
*   **Conclusion:** This validates the hypothesis that "Environmental Hardening" is a viable defense strategy even when the underlying vulnerability is unpatched.

---

## 4. Forensic Benchmarks: Observed Signatures
| Observable | Conventional Malware | Fileless (Red Team) |
| :--- | :--- | :--- |
| **Disk Footprint** | Binary in `/tmp` or `/bin` | **None** |
| **Filesystem Scans** | Detected by Hash/Signature | **Invisible** |
| **Process Maps** | Maps to `/tmp/malware` | Maps to `/memfd: (deleted)` |
| **Syscall Trace** | `open` -> `read` -> `execve` | `memfd_create` -> `write` -> `fexecve` |

---

## 5. Transition to Phase 3
The findings of Phase 2 confirmed the **Scanner Gap**. Because static analysis is 0% effective against this attack chain, the research pivoted to Phase 3 to develop **Dynamic eBPF Monitoring** capable of detecting the behavioral "heartbeat" of the `memfd_create` -> `fexecve` sequence.
