@startuml
' ====== Global style ======
skinparam monochrome true
skinparam shadowing false
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 13
skinparam linetype ortho
skinparam nodesep 80
skinparam ranksep 80
skinparam roundCorner 0
skinparam ArrowThickness 1.2
skinparam ArrowColor #333333

skinparam node {
  BorderColor #8d0909
  BorderThickness 2
  BackgroundColor #FFFFFF
  FontStyle bold
  FontSize 15
}

skinparam component {
  BorderColor #444444
  BorderThickness 1.2
  BackgroundColor #F0F0F0
  FontSize 13
}

skinparam database {
  BorderColor #555555
  BorderThickness 1
  BackgroundColor #E8E8E8
  FontSize 13
}

skinparam note {
  BorderColor #777777
  BackgroundColor #FAFAFA
  FontSize 12
}

' ====== Remote C2 ======
node "Remote Command & Control" as c2_node {
  component "C2 Listener\n(ncat)" as c2
}

' ====== Host machine ======
node "Host Machine  ·  Linux Kernel" as host {
  node "Container Namespace" as ns {
    component "Primary Loader\n(docker cp / bind-mount)" as loader
    component "Anonymous Memory\nmemfd_create(2)" as memfd
    component "Decrypted Payload\n(In-Memory Process)" as payload
  }

  database "Persistent Storage\nEndpoint Protection Domain" as disk
}

note bottom of disk
  <b>Scanner gap:</b> execution pathway
  bypasses persistent storage,
  evading static analysis.
end note

' ====== Flow arrows with vertical alignment and note-on-links ======
c2 -right-> loader
note top on link
  1. Entry point (docker exec)
end note

loader -down-> memfd
note right on link
  2. XOR decrypt & write
end note

memfd -down-> payload
note right on link
  3. fexecve(3) | proc replacement
end note

payload -left-> c2
note bottom on link
  4. Reverse shell (TCP)
end note

' ====== Layout Alignment Constraints ======
c2_node -[hidden]right-> host
payload -[hidden]down-> disk
@enduml