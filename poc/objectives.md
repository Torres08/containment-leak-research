# 3. Methodology & Solution Design
To test the hypothesis, this project uses an experimental approach to build a practical Proof of Concept (PoC). The primary goal is to prove that the Scanner Gap vulnerability allows malware to execute in RAM on both Docker and Apptainer, but the optimal mitigation strategies differ: Docker will be secured using a custom eBPF kernel monitor, while Apptainer will be secured using its powerful native flags.. 

## Phase 1: Infrastructure Initialization
Before any malware is executed, a controlled environment must be built to ensure the host system remains safe.

Objective: To create a strictly isolated testing environment using a Virtual Machine (VM) to act as the host machine. This includes installing both Docker (acting as the vulnerable baseline) and Apptainer. To test the hypothesis, containers will be configured to allow a baseline execution of the payload, setting the stage for the defensive tools. 
Measurable Goal: Successful installation and configuration of Docker and Apptainer within the VM, ensuring the environment is capable of facilitating a controlled fileless execution without risking the physical host. 
Timeline & Deadline: Starts now until April 23, 2026. The official Research Plan is due on April 23.

## Phase 2: Red Team PoC Development (The Attack)
This phase involves creating the offensive part of the experiment to demonstrate how the Scanner Gap allows a full system compromise.

Objective: To execute a three-step fileless attack against both container engines in their vulnerable baseline states: 
Loading: Use the memfd_create syscall to unpack malware directly into RAM, mimicking the Ezuri loader used by TeamTNT.
Escaping: Bypass the container’s isolation to access the host kernel.
Executing: Open a reverse shell to give an attacker remote command-line access to the host.
Measurable Goal: The attack is considered successful if a functional command-line prompt is established on the attacker's terminal from both Docker and Apptainer, proving that the shared-kernel architecture allows the malware to execute in RAM on both platforms. 
Timeline & Deadline: Start April 24 to May 14, 2026. The Research Poster submission is due on May 14.


## Phase 3: Blue Team Deployment (Native Hardening & Dynamic eBPF)
This phase focuses on applying the appropriate defensive countermeasures to each specific platform to neutralize the threat proven in Phase 2.
Objective: To implement and test two distinct platform-specific defensive strategies:
Docker Defense (eBPF): Deploy a custom dynamic monitoring tool using eBPF to watch the Linux kernel. Since Docker lacks strict default execution boundaries, this tool will intelligently intercept the memfd_create and execve syscalls to detect and block the attack.
Apptainer Defense (Native Flags): Relaunch the attack using Apptainer’s built-in execution tools—such as --drop-caps to strip execution privileges or --network none to isolate traffic. This proves that Apptainer has the native capability to trap the malware and block the reverse shell without requiring an external kernel monitor.
Measurable Goal: The Docker defense is successful if the eBPF program effectively intercepts and blocks the hidden memory execution. The Apptainer defense is successful if its native flags prevent the reverse shell and neutralize the threat internally.
Timeline & Deadline: Start May 15 to May 23, 2026. Findings will be presented at the research conference between May 17 and May 23


## Phase 4: Evaluation
This phase involves analyzing the experimental data to determine if the eBPF solution works and how the security features of different container engines affect the outcome.

Objective (Specific): To conduct a comprehensive comparative analysis of the two mitigation strategies. The evaluation will contrast how an external dynamic tool (eBPF) is required to secure Docker's architecture, whereas Apptainer's native design handles the threat internally.
Measurable Goal: The generation of a performance matrix tracking attack success rates under defensive conditions. This matrix will document the latency and system overhead of Docker's eBPF monitoring system alongside the effectiveness and simplicity of Apptainer’s native flag restrictions. 
Timeline & Deadline: Start May 24 to June 19, 2026. The Final Project report and PoC are due on June 19.
