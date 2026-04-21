# Containment Leak Research

**Student:** Juan Luis Torres Ramos  
**Program:** MICAC (Cybersecurity), Vilnius University (VU MIF)  
**Supervisor:** Assoc. Prof. Linas Bukauskas  
**Title:** Research on methods for application containment

---

## Hypothesis

Modern security containers (Docker/Apptainer) suffer from a **Scanner Gap**.  
Static file analysis fails to detect **ExecutableInExecutable** (T1027.002) attacks  malicious ELF binaries embedded inside legitimate files and executed directly from volatile memory via `memfd_create` + `fexecve`.

Dynamic system-call monitoring at the container boundary (**eBPF / strace**) successfully intercepts the payload's syscall chain before an escape or data leak occurs.

---

## Project Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | VM setup, Apptainer/Docker install, eBPF/strace config, Literature Review | ✅ Done |
| 2 | Red Team PoC Fileless Malware Loader | ✅ Done |
| 3 | Deploy PoC inside Apptainer sandbox | ⏳ Next |
| 4 | Dynamic Analysis & Evaluation (eBPF/strace logs) | 📋 Planned |

---

## Phase 2: Red Team PoC (`poc/`)

The PoC demonstrates the **T1027.002 (Software Packing / ExecutableInExecutable)** technique, as seen in real-world malware targeting containers and cloud environments:

- **VoidLink** (Check Point Research, 2026) cloud-native C2 framework, ELF object files loaded in-memory via a custom Plugin API operating on direct syscalls.
- **Ezuri** (LevelBlue SpiderLabs, 2021) Go-based memory loader using AES-256-CTR encrypted ELFs executed in-memory via `memfd_create`.
- **Shikitega** (AT&T Alien Labs, 2022) A stealthy multi-stage Linux malware that exploits Docker vulnerabilities and uses the Ezuri loader (`memfd_create`) to execute its crypto-miner entirely in memory.
- **TeamTNT Cryptojacking Botnet** (Various) A notorious cloud-focused threat actor that frequently leverages `memfd_create` and PRoot to hide their XMRig miners from disk-based container scanners.
- **Kinsing** (Aqua Security) Container-targeting malware that utilizes memory-backed execution and rootkits to evade detection by standard container security tools.
- **MITRE ATT&CK T1027.002** Obfuscated Files or Information: Software Packing.

### Build & Run

```bash
cd poc/

# Full build
make build

# Execute fileless loader (payload runs in-memory, no shell)
make run

# Full execution with Reverse Shell (bare host)
make shell

# Full execution with Reverse Shell from inside Docker container
make docker-shell

# Capture syscall trace (key evidence for Phase 4)
make strace

# Demonstrate static scanner gap
make verify
```

```
payload.c  ──[gcc -static]──►  bin/payload_elf
                                     │
                               [gen_xor_header]
                                     │ XOR key=0xAB
                                     ▼
                            src/payload_blob.h   (embedded byte array)
                                     │
loader.c  ─────────────────────────►├──[gcc]──►  bin/loader
                                     
[bin/loader] → memfd_create("") → write(payload) → fcntl(F_ADD_SEALS) → fexecve()
                                                                              │
                                       [payload_elf /bin/sh] ← connect() ←────┘
```

### Key Syscalls Generated (Detection Targets)

| Syscall | Description |
|---------|-------------|
| `memfd_create("", MFD_CLOEXEC\|MFD_ALLOW_SEALING)` | Creates anonymous in-memory file (blank name evasion) |
| `write(fd, payload_bytes, N)` | Writes decoded ELF into memory |
| `fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE...)` | Locks the payload read-only (TeamTNT technique) |
| `execveat(3, "", argv, envp, AT_EMPTY_PATH)` | Executes ELF from fd (fexecve internal) |
| `socket()`, `connect()`, `dup2()` | TCP reverse shell connection back to C2 |

**eBPF/Falco detection signature:** process launched with `/proc/<pid>/exe` → `/memfd: (deleted)`

---

## References

- Check Point Research (2026). *VoidLink: The Cloud-Native Malware Framework*. https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/
- LevelBlue SpiderLabs. *Malware Using New Ezuri Memory Loader*. https://www.levelblue.com/blogs/spiderlabs-blog/malware-using-new-ezuri-memory-loader
- AT&T Alien Labs (2022). *Shikitega - New stealthy malware targeting Linux*. https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
- Aqua Security (2020). *Kinsing Malware: Evolving Tactics in Container Environments*. https://www.aquasec.com/blog/threat-alert-kinsing-malware-container-vulnerability/
- Unit 42 / Palo Alto Networks. *TeamTNT Cryptojacking Operations*.
- MITRE ATT&CK. *T1027.002: Software Packing*. https://attack.mitre.org/techniques/T1027/002/
- Rice, L. (2023). *Container Security* (2nd Ed.). O'Reilly.
