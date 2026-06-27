@startuml
skinparam monochrome true
skinparam shadowing false
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 13
skinparam sequenceMessageAlign center
skinparam roundcorner 0
skinparam nodesep 40
skinparam ranksep 40

skinparam participant {
  BorderColor #222222
  BorderThickness 2
  BackgroundColor #FFFFFF
  FontStyle bold
  FontSize 15
}

skinparam note {
  BorderColor #777777
  BackgroundColor #FAFAFA
  FontSize 12
}

skinparam BoxFontSize 13
skinparam BoxFontStyle bold

box "Container Namespace" #F0F0F0
    participant "Loader Process" as L
end box

box "Host Kernel Space" #FFFFFF
    participant "Tracepoint\n(sys_enter)" as TP
    participant "BPF Hash Map\n(State Storage)" as MAP
    participant "LSM Hook\n(Enforcement)" as LSM
    participant "Ring Buffer\n(Telemetry)" as RB
end box

box "Host User Space" #F0F0F0
    participant "Defender Daemon" as D
end box

== Phase 1: Anonymous Allocation ==
L -> TP : syscall(memfd_create)
activate TP
TP -> MAP : Store PID & Timestamp
TP --> L : Return valid file descriptor (fd)
deactivate TP

== Phase 2: Stateful Execution Enforcement ==
L -> LSM : fexecve(fd)
activate LSM
LSM -> MAP : Fetch Timestamp for PID

alt Execution < 5s AND Process == "loader"
    LSM -> RB : Submit Alert Event
    LSM --> L : Return -EPERM (Block Execution)
    RB -> D : Trigger User-Space Alert
else Legitimate Execution Path
    LSM --> L : Return 0 (Allow Execution)
end
deactivate LSM
@enduml
