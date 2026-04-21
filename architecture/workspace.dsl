workspace "Containment Leak Research" "Simplified Fileless Malware Flow" {

    model {
        loader = softwareSystem "1. The Loader Program" "Appears safe to static disk scanners. Contains the XOR-encrypted malware payload." "Malware"

        memfd = softwareSystem "2. Invisible RAM File" "A nameless file living only in RAM, created via memfd_create(). It is sealed read-only after writing." "MemfdFile"

        payload = softwareSystem "3. The Hidden Payload" "Decrypted malware executed directly from RAM via fexecve(). Spawns a reverse shell." "Malware"

        ebpf = softwareSystem "4. The Security Monitor" "An eBPF/strace tool positioned outside the container to watch system calls." "SecurityTool"
        
        attackerListener = softwareSystem "Attacker C2" "Host listener accepting the reverse shell." "Attacker"

        loader -> memfd "1. Creates RAM file, decrypts payload, writes"
        memfd -> loader "2. Seals RAM file read-only"
        loader -> payload "3. Executes sealed payload directly from RAM"
        payload -> attackerListener "4. Escapes container via TCP Reverse Shell"

        loader -> ebpf "Detected signals: memfd_create, write, fcntl, execveat"
        payload -> ebpf "Detected signals: open(/etc/hostname), /memfd: (deleted) map"
    }

    views {
        systemLandscape "SimplifiedFlow" {
            include *
            autoLayout lr
            title "How Fileless Malware Operates (and how we catch it)"
            description "Simplified overview of the ExecutableInExecutable (T1027.002) attack."
        }

        styles {
            element "Element" {
                color #ffffff
            }
            element "Malware" {
                background #cc0000
                shape RoundedBox
            }
            element "MemfdFile" {
                background #facc2e
                color #000000
                shape Cylinder
            }
            element "SecurityTool" {
                background #00008b
                shape Hexagon
            }
            element "Attacker" {
                background #111111
                color #ffffff
                shape Robot
            }
        }
    }
}
