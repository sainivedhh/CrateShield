# Architecture Diagrams

## 1. Data Flow Diagram (DFD - Level 1)
```mermaid
graph TD
    User([User / CI Pipeline]) -->|Crate Name & Version| API(FastAPI Backend)
    API -->|Fetch tarball| CratesIO[(crates.io)]
    CratesIO -->|Return .crate| API
    API -->|Extract Code| Extractor(Tree-sitter Extractor)
    Extractor -->|Raw Signals| RAG(RAG Engine)
    RAG -->|Similarity Search| KB[(Vector DB / Chroma)]
    KB -->|Historical Incidents| RAG
    RAG -->|Prompt + Context| LLM(LLM API - Gemini/Claude)
    LLM -->|Malicious/Benign Decision| API
    API -->|JSON Report| User
```

## 2. Use Case Diagram (PlantUML)
*Note: You can render this directly in Jira using the PlantUML plugin or import it into draw.io.*

```plantuml
@startuml
left to right direction
skinparam packageStyle rectangle

actor "Security Analyst" as Analyst
actor "CI/CD Pipeline" as CI

package "CrateShield System" {
  usecase "Request Crate Scan" as UC1
  usecase "Extract AST Signals" as UC2
  usecase "Retrieve Past Incidents (RAG)" as UC3
  usecase "Classify via LLM" as UC4
  usecase "Generate Security Report" as UC5
}

Analyst --> UC1
CI --> UC1

UC1 ..> UC2 : <<include>>
UC2 ..> UC3 : <<include>>
UC3 ..> UC4 : <<include>>
UC4 ..> UC5 : <<include>>
@enduml
```
