# Empirical Evidence Logs: Container Containment and the Static Scanner Gap

This directory contains the telemetry traces, loader outputs, and benchmarks validating the containment profile results.

## Proof 1A — Docker Baseline Attack (Control Group)
- **Path**: `logs/proof1_baseline_attack.log`
- **Result**: Successful fileless execution. Payload executed from memory (`/memfd: (deleted)`), bypassed static scanning, and successfully connected a reverse shell inside Docker.

## Proof 1B — Apptainer Baseline Attack (Control Group)
- **Path**: `logs/proof1_baseline_attack_apptainer.log`
- **Result**: Successful fileless execution. Payload executed from memory (`/memfd: (deleted)`), bypassed static scanning, and successfully connected a reverse shell inside Apptainer.

## Proof 2 — eBPF LSM Defense (Stateful Dynamic Interception)
- **Path**: `logs/proof2_ebpf_block.log`
- **Result**: Intervention successful. The BPF-LSM hook `bprm_check_security` detected execution within the 5s window and terminated execution with `-EPERM`. Hook latency: **832 ns**.

## Proof 3 — Apptainer Seccomp Defense (Stateless Structural Containment)
- **Path**: `logs/proof3_apptainer_seccomp.log`
- **Result**: Intervention successful. The Seccomp filter rejected the `memfd_create` syscall at the entry boundary with `-EPERM`. Rejection latency: **284.18 ns**.

## Comparative Performance Benchmarks
- **Baseline `memfd_create` latency**: ~1263.99 ns (`logs/bench_seccomp_baseline.log`)
- **Seccomp rejection latency**: ~284.18 ns (`logs/bench_seccomp_filtered.log`)
- **eBPF LSM hook execution latency**: ~832 ns (`logs/bench_ebpf_lsm.log`)
