
@startuml
' IEEE Standard Styling for Grayscale Academic Publication
!theme plain
skinparam monochrome true
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 12
skinparam sequenceMessageAlign center
skinparam shadowing false
skinparam roundcorner 0

autonumber "<b>[00]</b>"

participant "Attacker (C2)" as A

box "User Space (Container)" #F0F0F0
    participant "Loader.c" as L
    participant "Payload (In-Memory)" as P
end box

box "Kernel Space (Host)" #FFFFFF
    participant "Host Kernel (RAM)" as K
    participant "Host monitor (eBPF/strace)" as M
end box

== Initialization ==
A -> L : Triggers Execution

group #DDDDDD The Scanner Gap (Diskless Zone)
    L -> K : syscall(SYS_memfd_create)
    activate K
    K --/ M : Hook: sys_enter_memfd_create
    K --> L : Return anonymous fd
    deactivate K
    
    note right of L: XOR-decodes payload into heap
    
    L -> K : write(fd, decoded_payload)
    note right of L: explicit_bzero() (Wipes heap)
    L -> K : fcntl(fd, F_ADD_SEALS)
end

== Control Flow Transfer ==

L -> K : fexecve(fd)
activate K
K --/ M : Hook: execveat (check fd seals)

note over L, P : Process Image Replacement (exec)
destroy L

create P
K -> P : Initiates Payload execution
deactivate K

P -> M : Leaves /memfd: (deleted) footprint
P -> A : Reverse Shell (socket, dup2, /bin/sh)
@enduml