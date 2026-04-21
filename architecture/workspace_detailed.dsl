workspace "Containment Leak Research" "In-Depth C4 Model — Fileless Malware PoC" {

    model {
        researcher = person "Researcher" "Runs the PoC and validates detection hypotheses."

        group "Testing Environment (Linux VM)" {

            blueTeam = softwareSystem "Security Monitor" "eBPF/strace tool monitoring system calls at the host kernel level." "SecurityTool"
            
            hostListener = softwareSystem "Attacker C2" "Host listener receiving the reverse shell (via docker0 bridge)." "SecurityTool"

            sandbox = softwareSystem "The Sandbox" "Docker/Apptainer container environment." {

                apptainer = container "Container Jail" "Enforces namespace isolation but allows network bridging and memfd." "Security Container"

                malwareStack = container "Malware Attack (PoC)" "Red Team components executing within the container." "Attack Framework" {

                    loader = component "1. The Disguise" "loader.c. Normal ELF binary containing XOR-encoded payload." "C Program"

                    memfd = component "2. Nameless RAM File" "/memfd: (deleted). Created via memfd_create(\"\") with MFD_ALLOW_SEALING." "RamFile"

                    sealing = component "2b. Memory Seal" "Locks RAM file read-only via fcntl(F_ADD_SEALS) before execution." "SealOp"

                    payload = component "3. The Hidden Payload" "payload.c. Executed directly from RAM. Spawns Reverse Shell." "HiddenMalware"
                }
            }
        }

        # -- High-level relationships --
        researcher -> malwareStack "Launches PoC"
        researcher -> blueTeam "Reviews detection logs"

        # -- Step-by-step malware execution flow --
        loader -> memfd "1-2. Creates nameless RAM file & writes decoded payload"
        memfd -> sealing "3. Seals file read-only (fcntl)"
        loader -> payload "4. Executes from RAM (fexecve / execveat)"
        payload -> apptainer "Read /etc/hostname"
        payload -> hostListener "5. Container Escape: TCP Reverse Shell"

        # -- Detection relationships --
        loader -> blueTeam "Detects memfd_create()"
        sealing -> blueTeam "Detects sealing fcntl()"
        loader -> blueTeam "Detects execveat(AT_EMPTY_PATH)"
        payload -> blueTeam "Detects network beacon & shell execution"
    }

    views {
        systemContext sandbox "SystemContext" {
            include *
            autoLayout lr
            title "Level 1: The Big Picture"
            description "The main actors."
        }

        container sandbox "ContainerView" {
            include *
            autoLayout tb
            title "Level 2: Inside the Sandbox"
            description "Malware components inside the Apptainer Jail."
        }

        component malwareStack "ComponentView" {
            include *
            autoLayout tb
            title "Level 3: The Fileless Execution Chain"
            description "Step-by-step memory execution and its detection signals."
        }

        styles {
            element "Person" {
                shape Person
                background #08427b
                color #ffffff
            }
            element "Software System" {
                background #438dd5
                color #ffffff
            }
            element "Container" {
                background #85bbf0
                color #000000
            }
            element "Component" {
                background #b5d5f5
                color #000000
                shape RoundedBox
            }
            element "SecurityTool" {
                background #228b22
                color #ffffff
                shape Hexagon
            }
            element "Attack Framework" {
                background #cc0000
                color #ffffff
            }
            element "RamFile" {
                background #facc2e
                color #000000
                shape Cylinder
            }
            element "SealOp" {
                background #ff8800
                color #000000
                shape Component
            }
            element "HiddenMalware" {
                background #8b0000
                color #ffffff
                shape Robot
            }
            element "C Program" {
                background #cc3300
                color #ffffff
            }
        }
    }
}
