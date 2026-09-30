# DevOps Documentation: CI/CD & Containerization

## 1. Containerization (Docker)
The CrateShield platform is fully containerized for consistent deployment across environments.
- **Base Image:** `python:3.11-slim`
- **Build Strategy:** Multi-layer caching (dependencies installed before source code to optimize build times).
- **Execution:** Runs the FastAPI backend via `uvicorn` on port 8000.

## 2. CI/CD Pipelines (GitHub Actions)
The repository uses GitHub Actions for continuous integration and deployment.

### 2.1 Continuous Integration (`.github/workflows/ci.yml`)
Runs on every `push` and `pull_request` to `main`:
1. **Linting & Type Checking:** Enforces code quality using `ruff` and `mypy`.
2. **Testing & Coverage:** Executes the `pytest` suite, ignoring LLM-dependent tests (to save API calls), and generates a coverage report.
3. **Docker Build Validation:** Builds the Docker container to ensure the application compiles correctly in an isolated environment.
4. **SonarQube/SonarCloud Analysis:** Sends coverage and code quality metrics to SonarQube.

### 2.2 Security Scanning (`.github/workflows/codeql.yml` & `dependabot.yml`)
1. **CodeQL:** Performs static application security testing (SAST) on the Python codebase.
2. **Dependabot:** Weekly scans for outdated or vulnerable dependencies.

### 2.3 Continuous Deployment (`.github/workflows/release.yml`)
Triggers when a new version tag (e.g., `v1.0.0`) is pushed.
- Archives the source code and configuration.
- Automatically generates a GitHub Release with release notes.
