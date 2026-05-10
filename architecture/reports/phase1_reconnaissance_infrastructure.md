# Phase 1: Reconnaissance & Infrastructure Setup

This phase focuses on the provisioning of the research environment and the establishment of the technical infrastructure required for cross-boundary containment analysis.

## 1. Executive Summary
To ensure scientific reproducibility and safety, all experiments are performed within a strictly isolated virtual machine environment. This infrastructure provides the necessary kernel features (`memfd_create`, `fexecve`) and runtime environments (Docker, Apptainer) to conduct high-fidelity containment research.

---

## 2. Environment Provisioning & Tooling
The following table details the host operating system and the essential tooling versions deployed for this research:

| Component | Version / Identifier | Purpose |
| :--- | :--- | :--- |
| **Operating System** | Debian GNU/Linux 13 (trixie) | Host OS for the research environment (`research-containment-01`). |
| **Linux Kernel** | `6.12.74+deb13+1-amd64` | Provides essential `memfd_create` (≥3.17) and `execveat` (≥3.19) system calls. |
| **Docker** | `26.1.5` | Target Runtime 1 (OCI-compliant daemon-based runtime). |
| **Apptainer** | `1.4.5` | Target Runtime 2 (HPC daemonless runtime). |
| **Victim Image** | `nginx:alpine` | Benign base image used to simulate a vulnerable web application. |
| **Compiler** | GCC `14.2.0` | Used to compile `loader.c`, `payload.c`, and the XOR obfuscation tool. |
| **C2 Listener** | Ncat `7.95` | Used on the host to catch the reverse shell from the containerized payload. |

---

## 3. Infrastructure Architecture
### Unified Pipeline
Both the Docker and Apptainer targets share identical source configurations (HTML files) and are managed through a unified `Makefile` pipeline. This ensures that any behavioral differences observed are due to the **container runtime isolation** and not differences in the application code.

### Network Configuration
The environment is configured to allow internal bridge networking (Docker) and shared host networking (Apptainer) to facilitate reverse shell callbacks while remaining isolated from the external internet.

### Laboratory Verification
The environment has been verified to support the following key research primitives:
*   **Anonymous Memory Files**: Confirmed support for `MFD_ALLOW_SEALING`.
*   **Static Evasion**: Confirmed that the compiler and XOR toolchain effectively bypass local static scanners.
*   **Kernel Exploitation**: Confirmed that `AF_ALG` modules are resident for Phase 2 escape research.
