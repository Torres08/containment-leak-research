# Phase 2: Red Team Development (Fileless Execution & Escape Analysis)

This document serves as the technical record of the offensive research phase, focusing on bypassing static analysis and implementing cross-boundary container escapes.

## 1. Executive Summary: The "Fileless" Advantage
The objective of Phase 2 was to prove that traditional on-disk scanning and signature-based detection are insufficient for modern container environments. By utilizing anonymous memory-backed file descriptors (`memfd_create`), we successfully executed a reverse-shell payload that never touched the container's disk, leaving no forensic footprint for standard `docker scan` or `clamav` tools to detect.

---

## 2. Technical Component: The Fileless Loader (`loader.c`)
The Red Team's primary weapon is a multi-stage fileless loader that implements MITRE Technique **T1027.002 (Software Packing)**.

### Stage 1: XOR Obfuscation (Static Evasion)
To bypass the "ELF Magic Number" detection used by forensic tools, the payload is XOR-encoded at build time (Key: `0xAB`). This transforms the standard `\x7fELF` header into `\xD4\xEE\xE7\xED`, blinding any scanner looking for executable signatures.

### Stage 2: Anonymous Memory Mapping (`memfd_create`)
The loader creates a nameless, RAM-only file descriptor.
*   **IoC Evasion:** By passing a blank name (`""`) to `memfd_create`, the process appears in `/proc/self/maps` as `/memfd: (deleted)`, which mimics benign anonymous memory mappings.

### Stage 3: Control Transfer (`fexecve`)
The loader reverses the XOR transformation in-memory and writes the bytes to the `memfd`. Finally, it invokes `fexecve()`.
*   **Result:** The kernel replaces the loader's image with the payload directly from RAM. No on-disk executable is ever created.

### Stage 4: The Payload (`payload.c`) - Interactive Reverse Shell
The "original" payload used to prove the fileless execution chain was a C-based reverse shell.
*   **Networking:** The payload dynamically detects its environment. In Docker, it connects to the bridge gateway (`172.17.0.1`); in Apptainer, it connects to the shared host loopback (`127.0.0.1`).
*   **Hijacking:** It uses the `dup2()` system call to redirect the standard streams (`stdin`, `stdout`, `stderr`) to the network socket.
*   **Execution:** It then invokes `/bin/sh`, granting the host attacker an interactive shell session running with the container's privileges.

---

## 3. Exploit Attempt: CVE-2026-31431 (Copy Fail)
We attempted to weaponize a kernel-level Page Cache poisoning vulnerability to achieve persistence on the host from within the container.

### The Objective
Target a host-mounted file (`/mnt/target_script`) and overwrite its Page Cache to execute an arbitrary command (`echo "!!! ESCAPE SUCCESSFUL !!!"`) on the host when the script is next invoked.

### The Technique
*   **Protocol:** `AF_ALG` (Linux Kernel Crypto API).
*   **Algorithm:** `authencesn(hmac(sha256),cbc(aes))`.
*   **Primitive:** Use `splice()` to move a reference of the host file's page into the kernel's cryptographic input buffer, then trigger a 4-byte out-of-bounds write via the AEAD "In-Place" optimization.

### The "Wall": Environmental Hardening
During testing on **Kernel 6.12.74 (Debian)**, the exploit encountered a persistent `EINVAL` (Invalid Argument) error during the `setsockopt(ALG_SET_KEY)` stage. 
*   **Findings:** Analysis confirmed that the kernel cryptographic modules were present, but strict API-level policy enforcement in this specific kernel build rejected the AEAD key instantiation.
*   **Conclusion:** This demonstrates that "Environmental Hardening" can effectively neutralize a known exploit chain even when the underlying vulnerable code exists in the kernel.

> [!IMPORTANT]
> **Code Preservation:** The full weaponized source code for the Copy Fail exploit, including the manual byte-mapping attempts to bypass this hardening, is preserved in the research branch: `research/copy-fail-weaponized`.

---

## 4. Execution & Verification (The Makefile Pipeline)
The Red Team phase used an automated `Makefile` to ensure consistent deployment across both Docker and Apptainer.

### Step 1: Catching the Shell
Before launching the attack, a listener must be established on the host:
```bash
# Terminal 1 (Host)
ncat -lvp 4444
```

### Step 2: Setup & Injection
The attack environment is prepared using automated `Makefile` targets:
*   **Docker:** `make docker-attack`
*   **Apptainer:** `make apptainer-attack`

### Step 3: Triggering the Loader
Once the environment is ready, the loader must be executed manually to initiate the fileless transition:
*   **Docker:** `docker exec -i victim-webapp /loader`
*   **Apptainer:** `apptainer exec deployment/apptainer-victim.sif /tmp/loader`

### Observed Result
In both cases, the host terminal (`ncat`) receives a root shell connection from the container. Running `ls -la /proc/self/exe` inside the shell reveals the forensic signature: `/memfd: (deleted)`, confirming that the shell is running entirely from memory.

---

## 5. Red Team Conclusions
*   **Docker/Apptainer Symmetry:** The fileless loader executed identically in both runtimes, proving that userspace isolation does not protect against memory-resident malware.
*   **Detection Gap:** Static analysis at the image level is 0% effective against packed, fileless payloads.
*   **Path to Phase 3:** Since static analysis fails, the Blue Team must transition to **Dynamic eBPF Monitoring** to detect the behavioral signals of the `memfd_create` -> `execve` chain.
