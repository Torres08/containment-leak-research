@startuml
skinparam monochrome true
skinparam shadowing false
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 16
skinparam linetype ortho
skinparam nodesep 100
skinparam ranksep 100

skinparam activity {
  BorderColor #222222
  BorderThickness 2
  BackgroundColor #FFFFFF
  FontStyle bold
  FontSize 18
}

skinparam note {
  BorderColor #777777
  BackgroundColor #FAFAFA
  FontSize 15
}

skinparam swimlane {
  BorderColor #222222
  BorderThickness 2
  TitleFontSize 16
  TitleFontStyle bold
}

|Container Namespace (User Space)|
start
:Apptainer instantiates runtime\n(applies declarative JSON profile);
:Loader executes payload sequence;
:Invoke syscall(memfd_create);

|Host Kernel Space (Seccomp-BPF)|
:Kernel evaluates system call\nagainst immutable matrix;

note right
  **Structural Deny List:**
  1. memfd_create
  2. execveat
end note

if (Syscall matches deny list?) then (Yes)
  :Kernel immediately returns -EPERM;
  
  |Container Namespace (User Space)|
  :Process receives EPERM\n(Operation not permitted);
  :Execution terminates (Attack neutralized);
  stop
else (No)
  |Host Kernel Space (Seccomp-BPF)|
  :System call permitted;
  
  |Container Namespace (User Space)|
  :Continue legitimate execution;
  detach
endif
@enduml