@startuml
' ====== Global style ======
skinparam monochrome true
skinparam shadowing false
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 13
skinparam linetype ortho
skinparam nodesep 60
skinparam ranksep 90
skinparam roundCorner 0
skinparam ArrowThickness 1.2
skinparam ArrowColor #333333

' Rotate layout: down is right, right is down
left to right direction

skinparam node {
  BorderColor #222222
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

skinparam note {
  BorderColor #777777
  BackgroundColor #FAFAFA
  FontSize 12
}

' === Docker Environment ===
node "Docker (Isolated Network Namespace)" as docker_env {
    node "Container Namespace" as d_ns {
        component "Fileless Payload" as d_payload
        component "Interface eth0" as d_eth0
    }
    
    component "veth-pair" as d_veth
    
    node "Host Network Namespace" as d_host {
        component "docker0 bridge(NAT: 172.17.0.1)" as d_bridge
        component "Host Listener(0.0.0.0:4444)" as d_listen
    }
    
    d_payload -down-> d_eth0
    note left on link
      1. connect()
    end note

    d_eth0 -down-> d_veth
    note left on link
      2. virtual link
    end note

    d_veth -down-> d_bridge 

    d_bridge -down-> d_listen
    note right on link
      3. NAT forward
    end note
}

' === Apptainer Environment ===
node "Apptainer (Shared Host Namespace)" as apptainer_env {
    node "Host Network Namespace" as a_host {
        component "Fileless Payload" as a_payload
        component "Interface lo (127.0.0.1)" as a_lo
        component "Host Listener(127.0.0.1:4444)" as a_listen
    }
    
    a_payload -down-> a_lo
    note left on link
      1. connect()
    end note

    a_lo -down-> a_listen
    note left on link
      2. local route
    end note
}

' Stack environments vertically (right corresponds to down under rotation)
docker_env -[hidden]right-> apptainer_env
@enduml