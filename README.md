# Research on methods for application containment PoC

This repository contains the source code, kernel telemetry modules, containment profiles, and architectural models developed to investigate the Static Scanner Gap in container runtimes. The project demonstrates an ExecutableInExecutable (MITRE ATT&CK T1027.002) evasion vector using memory-backed anonymous files (`memfd_create` + `fexecve`) and implements two defense strategies: 
1. stateful dynamic interception via eBPF-LSM  
2. stateless structural containment via Seccomp.

---

## 1. Experimental Baseline

To guarantee the reproducibility of the execution latencies and mitigation responses, the research environment must conform to the following hardware and software specification:

### Host Hardware Platform
*   **Architecture**: x86_64 CPU (supporting VT-x virtualization).
*   **Processor Core Isolation**: To eliminate scheduler-induced latency jitter, the host Linux kernel must be booted with the `isolcpus=2,3` boot parameter, reserving logical cores 2 and 3 exclusively for benchmarking.

### Operating System and Kernel
*   **OS Distribution**: Debian GNU/Linux 13 (trixie)
*   **Linux Kernel**: Version `6.12.74-amd64` or higher (configured with `CONFIG_BPF_LSM=y` and `CONFIG_SECURITY_LANDLOCK=y`).

### Container Runtimes and Toolchains
*   **Docker Engine**: Version `26.1.5`
*   **Apptainer**: Version `1.4.5` (built with squashfs-tools support).
*   **Compiler & BPF Tooling**: GCC `13.2.0`, Clang `17.0.6`, `bpftool` (v7.4.0), and `libbpf-dev` (v1.3.0).

---

## 2. Compilation Directives

The build system is managed via GNU Make. It compiles the userspace binaries, encodes the evasion payload, and compiles the eBPF kernel object files.

### 2.1 Core Evasion Framework
To compile the Red Team Proof-of-Concept (PoC):
```bash
make build
```
This target executes the following linear pipeline:
1.  **Payload Compilation**: Compiles `src/payload.c` into a fully static target ELF binary (`bin/payload_elf`).
2.  **Encoder Generation**: Compiles `src/gen_xor_header.c` to generate the XOR encoder utility (`bin/gen_xor_header`).
3.  **XOR Obfuscation**: Feeds the raw bytes of `bin/payload_elf` through the encoder, outputting `src/payload_blob.h`, which contains the payload bytes obfuscated with key `0xAB` (evading simple ELF magic signature matching).
4.  **Loader Compilation**: Compiles `src/loader.c` (incorporating `src/payload_blob.h`) to output the final execution binary (`bin/loader`).

### 2.2 Kernel Telemetry and Dynamic Blocker
To compile the eBPF LSM security module and its userspace monitor:
```bash
make bpf-build
```
This target executes:
1.  **Vmlinux Header Extraction**: Invokes `bpftool btf dump file /sys/kernel/btf/vmlinux format c` to generate the kernel definition header `bpf/vmlinux.h`.
2.  **BPF Bytecode Compilation**: Compiles the C code in `bpf/memfd_exec_block.bpf.c` using Clang target BPF to produce the kernel-space ELF bytecode `bpf/memfd_exec_block.bpf.o`.
3.  **Userspace Monitor Compilation**: Compiles `bpf/memfd_exec_block.c` with GCC and links against `libbpf` to output the control daemon (`bin/memfd_exec_block`).

---

## 3. Execution Parameters

To ensure empirical accuracy, all benchmark runs must use processor pinning via `taskset` to target isolated CPU cores. On systems with 2 logical processors, pin monitoring daemons to Core `0` and benchmark workloads to Core `1`.

### 3.1 Baseline Attack (Control Group)
This execution establishes the unmitigated attack pathway on both container engines to demonstrate the vulnerability.

#### 3.1.1 Docker Baseline Attack
1.  **Terminal 1 (C2 Listener)**: Start the netcat listener on Core 1:
    ```bash
    taskset -c 1 ncat -lvp 4444
    ```
2.  **Terminal 2 (Docker Attack Execution)**: Build the victim container and run the loader:
    ```bash
    # Recompile payload for Docker bridge (172.17.0.1) and copy to container
    make docker-attack
    
    # Run the loader inside the container (pinned to Core 1)
    taskset -c 1 docker exec -i victim-webapp /loader
    ```

#### 3.1.2 Apptainer Baseline Attack
1.  **Terminal 1 (C2 Listener)**: Start the netcat listener on Core 1:
    ```bash
    taskset -c 1 ncat -lvp 4444
    ```
2.  **Terminal 2 (Apptainer Attack Execution)**: Prepare the SIF image and copy the loader:
    ```bash
    # Recompile payload for loopback (127.0.0.1) and copy to host /tmp
    make apptainer-attack
    
    # Run the loader inside Apptainer (pinned to Core 1)
    taskset -c 1 apptainer exec deployment/apptainer-victim.sif /tmp/loader
    ```

### 3.2 Docker eBPF Defense (Stateful Dynamic Interception)
This test validates the dynamic blocking of memory execution within a Docker container using the compiled eBPF LSM program.

1.  **Terminal 1 (LSM Monitor)**: Run the eBPF control daemon in host space, pinned to Core 0 (requires sudo):
    ```bash
    make docker-defense
    ```
2.  **Terminal 2 (C2 Listener)**: Launch the listener on Core 1:
    ```bash
    taskset -c 1 ncat -lvp 4444
    ```
3.  **Terminal 3 (Container Workload)**: Instantiate the Docker web container and run the loader pinned to Core 1:
    ```bash
    # Recompile payload with the docker bridge IP (172.17.0.1)
    make docker-attack
    
    # Run the injected loader inside the container
    taskset -c 1 docker exec -i victim-webapp /loader
    ```

### 3.3 Apptainer Seccomp Defense (Stateless Structural Containment)
This test validates the immediate rejection of anonymous allocations inside an Apptainer container.

1.  **Terminal 1 (C2 Listener)**: Start the listener on Core 1:
    ```bash
    taskset -c 1 ncat -lvp 4444
    ```
2.  **Terminal 2 (Container Execution)**: Initialize the hardened Apptainer container on Core 1:
    ```bash
    # Recompile target for loopback C2 and prepare environment
    make apptainer-defense
    
    # Execute Apptainer with the Seccomp profile JSON attached
    taskset -c 1 apptainer exec --security seccomp:deployment/seccomp_memfd_exec.json deployment/apptainer-victim.sif /tmp/loader
    ```

---

## 4. Verification Criteria

Reviewers must inspect the standard output and error descriptors of the loader to verify that the mitigations successfully terminated execution at the correct system call boundary.

### 4.1 Stateful eBPF Mitigation Verification
During a blocked execution run under Docker with the eBPF LSM module active, the loader output must conform to the following trace:
```plain
[LOADER] Starting fileless execution sequence...
[LOADER] Stage 1: Creating anonymous in-memory file descriptor (memfd)...
[LOADER] SUCCESS: Obtained fd 3
[LOADER] Stage 2: Writing 749296 bytes of decrypted payload into fd 3...
[LOADER] SUCCESS: Wrote 749296 bytes
[LOADER] Stage 3: Adding write seals to prevent modification...
[LOADER] SUCCESS: File sealed
[LOADER] Stage 4: Transferring execution control via fexecve...
[LOADER] ERROR: fexecve failed: Permission denied
```
*   **Verification Check**:
    1.  The output confirms that `memfd_create` and writing/sealing **succeeded** (fd 3 created).
    2.  `fexecve` (internally invoking the `execveat` syscall) failed with `Permission denied` (`-EPERM`).
    3.  This confirms the mitigation triggered at the **LSM execution boundary** (after allocation but prior to execution), matching the flow in **`diagram5.md`**.

### 4.2 Stateless Seccomp Mitigation Verification
During a blocked execution run under Apptainer with the Seccomp filter active, the loader output must conform to the following trace:
```plain
[LOADER] Starting fileless execution sequence...
[LOADER] Stage 1: Creating anonymous in-memory file descriptor (memfd)...
[LOADER] ERROR: memfd_create failed: Operation not permitted
```
*   **Verification Check**:
    1.  The loader failed immediately at Stage 1.
    2.  `memfd_create` failed with `Operation not permitted` (`-EPERM`).
    3.  This confirms the mitigation triggered at the **system call entry boundary**, completely preventing the memory file descriptor from allocating memory, matching the flow in **`diagram6.md`**.

---

## 5. Architectural Map & UML Alignment

The repository's execution logic is mapped to the architectural specifications in the `diagrams/` directory:

*   **`diagram1.md` (System Deployment Model)**: Represents the evasion pathway (Scanner Gap) showing how the payload runs in anonymous memory to bypass disk scanners.
*   **`diagram2.md` (Execution Sequence Model)**: Represents the sequential interactions between the loader, the host kernel, and the BPF telemetry probes.
*   **`diagram3.md` (Network Topology Model)**: Represents the reverse shell routing topology for the Docker bridge network and the Apptainer loopback network.
*   **`diagram4.md` (Loader Execution Pipeline)**: Represents the block diagram showing the progression of stages in the loader's execution sequence.
*   **`diagram5.md` (eBPF LSM Stateful Model)**: Represents the stateful correlation and hooks used by eBPF LSM to intercept the execution window.
*   **`diagram6.md` (Seccomp Stateless Model)**: Represents the stateless system call entry validation policy applied by Seccomp.
