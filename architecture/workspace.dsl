workspace "Containment Leak Research" "Fileless Malware — Container Runtime Comparison" {

    configuration {
        scope softwaresystem
    }

    properties {
        "structurizr.inspection.*" "ignore"
    }

    model {

        # ───────────────────────────────────────────────
        # VIEW 1 — Simplified Attack Chain
        # ───────────────────────────────────────────────
        loader = softwareSystem "Loader" "XOR-encrypted payload. No malware visible on disk." "Malware"
        memfd = softwareSystem "RAM File" "Anonymous in-memory file via memfd_create(). Never touches disk." "MemfdFile"
        payload = softwareSystem "Payload" "Executed from RAM via fexecve(). Spawns reverse shell." "Malware"
        monitor = softwareSystem "Security Monitor" "eBPF/Falco/strace watching syscalls outside the container." "SecurityTool"
        c2_simple = softwareSystem "Attacker C2" "ncat -lvp 4444 — receives the reverse shell." "C2Tag"

        loader -> memfd "memfd_create + write + seal" "Syscall"
        memfd -> payload "fexecve (no on-disk ELF)" "Syscall"
        payload -> c2_simple "Reverse shell" "TCP"
        loader -> monitor "memfd_create, fcntl, execveat" "eBPF"
        payload -> monitor "/memfd: (deleted) in /proc/maps" "eBPF"

        # ───────────────────────────────────────────────
        # GLOBAL ELEMENTS
        # ───────────────────────────────────────────────
        c_attacker = person "Attacker (Container)" "Exploits RCE to inject and execute the loader." "AttackerTag"
        dn_attacker = person "Attacker (Docker Net)" "ncat -lvp 4444 on host." "AttackerTag"
        an_attacker = person "Attacker (Apptainer Net)" "ncat -lvp 4444 on host." "AttackerTag"
        
        c_c2 = softwareSystem "Attacker C2 (Container)" "ncat listener on host." "C2Tag"
        
        c_blueTeam = softwareSystem "Security Monitor (Host)" "eBPF/Falco monitoring syscalls at host kernel level." "SecurityTool"

        # ───────────────────────────────────────────────
        # SINGLE SOFTWARE SYSTEM
        # ───────────────────────────────────────────────
        researchInfra = softwareSystem "Research Infrastructure" "The target environments being tested for containment leaks." {
            
            group "Container Attack Surface" {
                c_nginx = container "nginx web server" "nginx:alpine victim. Serves html/index.html." "nginx"
                c_loader = container "Injected Loader" "Injected by attacker. Not in the image layer." "Malware"
                c_memfd = container "Fileless Execution" "memfd_create → write → seal → fexecve. All segments: /memfd: (deleted)." "RamFile"
                c_shell = container "Reverse Shell" "/bin/sh via dup2 TCP socket." "Shell"
            }

            group "Docker Network Stack" {
                dn_hostNS = container "Host Network NS (Docker)" "eth0, lo — listener bound to 0.0.0.0:4444." "NetworkD"
                dn_bridge = container "docker0 bridge" "Virtual bridge. Gateway: 172.17.0.1. NAT between host and containers." "Bridge"
                dn_ctrNS = container "Container Network NS" "Isolated stack. Own lo. Cannot reach host lo directly." "NetworkD"
                dn_payload = container "Payload (in Docker container)" "Calls connect(172.17.0.1, 4444)." "Malware"
                dn_shell = container "Reverse Shell (Docker Net)" "stdio redirected to TCP socket." "Shell"
            }

            group "Apptainer Network Stack" {
                an_hostNS = container "Shared Host Network NS" "Apptainer shares this by default. lo = 127.0.0.1 is the real host loopback." "NetworkA"
                an_sandbox = container "Apptainer Sandbox" "Filesystem + PID isolated. Network namespace NOT isolated." "Sandbox"
                an_payload = container "Payload (in Apptainer container)" "Calls connect(127.0.0.1, 4444) — reaches host listener directly." "Malware"
                an_shell = container "Reverse Shell (Apptainer Net)" "stdio redirected to TCP socket." "Shell"
            }
        }

        # ───────────────────────────────────────────────
        # RELATIONSHIPS
        # ───────────────────────────────────────────────
        c_attacker -> c_nginx "RCE exploit" "HTTPS"
        c_attacker -> c_loader "Injects loader binary" "API/FS"
        c_loader -> c_memfd "XOR decode → memfd_create → fexecve" "Syscall"
        c_memfd -> c_shell "Spawns shell on TCP socket" "Syscall"
        c_shell -> c_c2 "Reverse shell connection" "TCP"
        c_loader -> c_blueTeam "execve signal" "eBPF"
        c_memfd -> c_blueTeam "memfd_create, fcntl(F_ADD_SEALS), execveat" "eBPF"
        c_shell -> c_blueTeam "socket, connect, dup2" "eBPF"

        dn_payload -> dn_shell "Spawns" "Syscall"
        dn_shell -> dn_ctrNS "connect(172.17.0.1, 4444)" "TCP"
        dn_ctrNS -> dn_bridge "Routed to bridge gateway" "TCP"
        dn_bridge -> dn_hostNS "Forwarded to host listener" "TCP"
        dn_hostNS -> dn_attacker "Shell received" "TCP"

        an_payload -> an_shell "Spawns" "Syscall"
        an_shell -> an_sandbox "connect(127.0.0.1, 4444)" "TCP"
        an_sandbox -> an_hostNS "Direct access — no NAT, no bridge" "TCP"
        an_hostNS -> an_attacker "Shell received" "TCP"
    }

    views {

        systemLandscape "View1_AttackChain" {
            include loader memfd payload monitor c2_simple
            autoLayout lr
            title "1. Fileless Attack Chain (T1027.002)"
            description "How the loader executes the payload from RAM and phones home."
        }

        systemContext researchInfra "View2_SystemContext" {
            include c_attacker dn_attacker an_attacker c_c2 c_blueTeam researchInfra
            autoLayout tb
            title "2. System Context: Research Infrastructure"
            description "The target environments being tested for containment leaks."
        }

        container researchInfra "View3_ContainerAttack" {
            include c_attacker c_blueTeam c_c2 c_nginx c_loader c_memfd c_shell
            autoLayout tb
            title "3. Container Fileless Attack Flow"
            description "Generic container victim (Docker or Apptainer). Loader injected. Execution in RAM. C2 via reverse shell."
        }

        container researchInfra "View4_NetworkComparison" {
            include dn_attacker dn_hostNS dn_bridge dn_ctrNS dn_payload dn_shell
            include an_attacker an_hostNS an_sandbox an_payload an_shell
            autoLayout tb
            title "4. Network: Docker Isolated NS vs Apptainer Shared NS"
            description "Docker: payload must route through docker0 bridge NAT (172.17.0.1:4444) to reach the host listener. Apptainer: payload connects directly to host loopback (127.0.0.1:4444) — no bridge, no NAT."
        }

        styles {
            element "Person" {
                background #111111
                color #ffffff
                shape Person
            }
            element "AttackerTag" {
                background #111111
                color #ffffff
                shape Person
            }
            element "Software System" {
                background #438dd5
                color #ffffff
            }
            element "Container" {
                background #85bbf0
                color #000000
            }
            element "Malware" {
                background #cc0000
                color #ffffff
                shape RoundedBox
            }
            element "MemfdFile" {
                background #facc2e
                color #000000
                shape Cylinder
            }
            element "RamFile" {
                background #facc2e
                color #000000
                shape Cylinder
            }
            element "Shell" {
                background #8b0000
                color #ffffff
                shape Robot
            }
            element "SecurityTool" {
                background #228b22
                color #ffffff
                shape Hexagon
            }
            element "C2Tag" {
                background #8b0000
                color #ffffff
                shape WebBrowser
            }
            element "nginx" {
                background #009900
                color #ffffff
                shape RoundedBox
            }
            element "Host" {
                background #1168bd
                color #ffffff
            }
            element "NetworkD" {
                background #0055a4
                color #ffffff
                shape Component
            }
            element "NetworkA" {
                background #006600
                color #ffffff
                shape Component
            }
            element "Bridge" {
                background #e6a817
                color #000000
                shape Component
            }
            element "Sandbox" {
                background #5b8db8
                color #ffffff
                shape Component
            }
        }
    }
}
