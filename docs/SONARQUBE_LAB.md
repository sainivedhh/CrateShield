# SonarQube Static Code Analysis — Lab Guide

## Aim
To perform static code analysis of the **CrateShield** Python project using SonarQube
running locally via Docker and identify code quality, security vulnerabilities,
and code smells in the source code.

## Software Requirements
- Windows 10/11 with Docker Desktop installed
- Docker Compose (included with Docker Desktop)
- Web browser (Chrome / Edge)
- PowerShell / Terminal
- CrateShield source code (`src/`, `tests/`)

---

## Experiment Flow

```
Start Docker Desktop
        ↓
Start SonarQube Container  (docker-compose up sonarqube)
        ↓
Open SonarQube Dashboard   (http://localhost:9000)
        ↓
Create Project             (manual key: CrateShield)
        ↓
Generate Project Token     (copy to .env as SONAR_TOKEN)
        ↓
Generate coverage.xml      (pytest --cov-report=xml)
        ↓
Run SonarScanner           (docker-compose run --rm --profile scan sonarscanner)
        ↓
Open SonarQube Dashboard
        ↓
Analyze Issues
    ├── Bugs
    ├── Vulnerabilities
    ├── Security Hotspots
    ├── Code Smells
    └── Quality Gate
```

---

## Step-by-Step Instructions

### Step 1 — Start SonarQube via Docker

Open PowerShell in your project root and run:

```powershell
docker-compose up sonarqube -d
```

Wait ~60 seconds for SonarQube to initialize. You can watch it with:
```powershell
docker-compose logs -f sonarqube
```
When you see `SonarQube is operational` in the logs, proceed.

---

### Step 2 — Open SonarQube Dashboard

Open your browser and navigate to:
```
http://localhost:9000
```
- **Default login:** `admin` / `admin`
- You will be prompted to change the password on first login.

---

### Step 3 — Create a Project

1. Click **"Create a local project"**
2. Set **Project display name:** `CrateShield`
3. Set **Project key:** `CrateShield`
4. Set **Branch name:** `main`
5. Click **"Set up"**
6. Choose **"Locally"** as the analysis method

---

### Step 4 — Generate a Project Token

1. Click **"Generate a token"**
2. Set token name: `crateshield-scanner`
3. Click **"Generate"**
4. **Copy the token** — you will only see it once!
5. Add it to your `.env` file:
```bash
SONAR_TOKEN=squ_your_generated_token_here
```

---

### Step 5 — Generate Coverage Report

Before running the scanner, generate the coverage XML report:

```powershell
.venv\Scripts\activate
pytest -m "not llm" --cov=crateshield --cov-report=xml --tb=short -q
```

This creates `coverage.xml` in your project root, which SonarQube uses to
display test coverage on the dashboard.

---

### Step 6 — Run SonarScanner

With your `SONAR_TOKEN` set in `.env`, run the scanner:

```powershell
# Load env vars from .env
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^#][^=]+)=(.*)$') { [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2]) }
}

# Run the scanner
docker-compose --profile scan run --rm sonarscanner
```

The scanner will:
1. Read `sonar-project.properties` for project config
2. Upload your source code to the local SonarQube server
3. Upload `coverage.xml` for coverage metrics

---

### Step 7 — Analyze Results

Go back to `http://localhost:9000` → your **CrateShield** project.

You will see:
| Metric | What to look for |
|---|---|
| **Bugs** | Logic errors, null pointer risks |
| **Vulnerabilities** | Hardcoded secrets, injection risks |
| **Security Hotspots** | Subprocess calls, eval(), open() |
| **Code Smells** | Duplications, long functions, dead code |
| **Coverage** | % of code covered by pytest |
| **Quality Gate** | Overall pass/fail status |

---

## Stop SonarQube

When done, stop the container:
```powershell
docker-compose stop sonarqube
```

Data is persisted in Docker volumes, so your project and results are saved.
