@startuml
!theme plain
skinparam monochrome true
skinparam shadowing false
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 12
skinparam roundcorner 0

left to right direction

title Fileless ELF Execution Chain

rectangle "memfd_create" as step1
rectangle "write" as step2
rectangle "fcntl(F_ADD_SEALS)" as step3
rectangle "fexecve (execveat)" as step4

step1 --> step2
step2 --> step3
step3 --> step4

@enduml
