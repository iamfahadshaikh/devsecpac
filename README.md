# devsecpac (Universal Autonomous DevSecOps Orchestrator)

DevSecPac is an autonomous multi-engine security scanning orchestrator. It automatically discovers repository structures, executes relevant security tools across SAST, SCA, Secrets, IaC, Containers, Kubernetes, and Mobile stacks, unifies and deduplicates findings, generates local remediation patches, and exports results to CI/CD and ASPM platforms.

---

## Security Engines and Capabilities

Below is the complete matrix of integrated engines, their specific security role, the protection gained by running them, and the security risk exposure if skipped:

| Security Engine | Security Category | Purpose and Why It Is Included | What Happens If Used | What Happens If Skipped |
| :--- | :--- | :--- | :--- | :--- |
| **Gitleaks** | Secret Detection | Scans git commits, branches, and staged files for exposed API keys, private tokens, and passwords using pattern matching. | Catches leaked credentials prior to deployment, preventing account compromise. | High risk of leaking production credentials to public or shared git history. |
| **TruffleHog** | Deep Secret Scanning | Uses Shannon entropy and comprehensive secret verification algorithms across entire commit histories. | Finds rotated or legacy credentials buried deep in past commit trees. | Hidden, forgotten keys remaining in historical commits remain undetected. |
| **Semgrep** | Fast SAST & Guardrails | Multi-language static code analysis for Python, JS/TS, Go, Java, Docker, and configs without compilation. | Detects injection flaws (XSS, SQLi), insecure library calls, and logic flaws in seconds. | Application logic bugs and common CVE design patterns enter production code. |
| **Hadolint** | Dockerfile Linter | AST-based Dockerfile parser enforcing container best practices and non-root execution. | Flags root execution, untagged images, unpinned packages, and insecure curl/wget pipes. | Container images risk privilege escalation, bloated layers, and supply-chain tampering. |
| **GitHub CodeQL** | Semantic SAST | Compiles source code into relational database models to track deep taint-flow paths. | Flags complex, multi-hop remote code execution and cross-file injection paths. | Inter-procedural taint flow vulnerabilities slip past simple regex linters. |
| **SonarQube** | SAST & Quality Gate | Enterprise code quality, maintainability, test coverage, and security vulnerability analyzer. | Enforces strict release quality gates and identifies long-term maintainability debt. | Technical debt and security code smells accumulate unchecked across sprints. |
| **Checkov** | IaC Security | Scans Terraform, CloudFormation, Kubernetes, ARM, and Docker compose manifests against compliance benchmarks. | Catches open AWS S3 buckets, overly permissive IAM roles, and missing encryption. | Cloud infrastructure misconfigurations reach production, causing cloud leaks. |
| **Kubeconform** | Kubernetes Schema | Validates Kubernetes YAML against official OpenAPI and custom resource definition (CRD) schemas. | Blocks invalid API versions, missing spec fields, and syntax mistakes before deployment. | `kubectl apply` failures or silent cluster deployment rejections during rollouts. |
| **Kyverno CLI** | K8s Policy as Code | Evaluates Kubernetes manifests against security admission policies (e.g. Pod Security Standards). | Enforces mandatory read-only root filesystems, memory limits, and drops Linux capabilities. | Workloads run with host namespaces or excessive kernel privileges in cluster. |
| **Aqua Trivy** | Filesystem & Vuln SCA | Deep scanning of OS packages, application lockfiles, and container base layers. | Detects known CVEs in installed dependencies with severity and fixed version metadata. | Vulnerable third-party dependencies are deployed with unpatched vulnerabilities. |
| **OWASP Dependency-Check** | Software Composition (SCA) | Analyzes project dependencies for known published vulnerabilities against NVD CVE feeds. | Comprehensive enterprise visibility across Java, .NET, Node, and Python packages. | Dependency vulnerabilities in legacy libraries remain hidden without CVE alerts. |
| **Syft** | SBOM Generation | Inspects project dependencies and packages to build a machine-readable software inventory. | Produces CycloneDX-compliant SBOMs required by federal and compliance mandates. | Zero visibility into software supply chain; non-compliant with standard audits. |
| **Cosign (Sigstore)** | Supply Chain Attestation | Cryptographically signs generated SBOM artifacts and container images. | Guarantees pipeline tamper-proof provenance and satisfies SLSA level 2/3 requirements. | Inability to prove that build artifacts were not tampered with post-build. |
| **OWASP ZAP** | Baseline DAST | Dynamic application security testing of running HTTP web endpoints and APIs. | Identifies active runtime issues: missing CSP/HSTS headers, cookie flags, and active XSS. | Runtime misconfigurations and missing transport security go unnoticed in production. |
| **Schemathesis** | API Contract Security | Property-based fuzzing of OpenAPI, Swagger, and GraphQL interface schemas. | Discovers edge-case unhandled server 500 exceptions, type crashes, and input parsing errors. | API endpoints crash when receiving unexpected or malformed customer requests. |
| **Nmap** | Port & Service Discovery | Scans network targets and localhost to detect exposed ports and service banners. | Identifies open backend database ports or debug listeners inadvertently exposed. | Database, management, or debug ports remain exposed to external networks. |
| **MobSF** | Mobile Security (SAST) | Security analysis of Android and iOS application source directories and manifests. | Detects exported activities, insecure storage, and broken permission boundaries. | Mobile client secrets and insecure local storage vulnerabilities reach mobile stores. |

---

## Usage Variations

DevSecPac can be consumed in two primary workflows:
1. **As a Standalone Python Package** (`pip install devsecpac`)
2. **As an Air-Gapped Docker Container** (`docker run iamfahadshaikh/devsec-cli:latest`)

---

### Section 1: Running as a Python Package

Install the orchestrator into your Python environment:

```bash
pip install devsecpac
```

#### 1. Setup Required Tools Automatically
DevSecPac includes an autonomous installer that downloads and configures missing binary security engines into your local user path (`~/.local/bin`):
```bash
devsec setup
```

#### 2. Check Tool Discovery
Inspect which scanners are active and detected in your environment:
```bash
devsec info
```

#### 3. Run Autonomous Full Scan
Scan the current directory or target project path:
```bash
devsec scan .
```

#### 4. Run Targeted Scanners
Select specific security engines using comma-separated engine names:
```bash
# Scan secrets and static code
devsec scan . -t gitleaks,semgrep

# Scan container Dockerfile and Kubernetes manifests
devsec scan . -t hadolint,checkov,kubeconform
```

#### 5. Scan a Remote Git Repository
Ingest and scan a remote repository directly:
```bash
devsec scan -r https://github.com/owner/repository.git -t semgrep,hadolint
```

#### 6. Export to Enterprise ASPM (DefectDojo)
Push deduplicated vulnerability findings directly into DefectDojo:
```bash
devsec scan . --defectdojo-push \
  --defectdojo-url "http://localhost:8080" \
  --defectdojo-key "your-api-token"
```

#### 7. Generate Remediation Patch
Create a unified Git patch containing recommended fixes for local verification:
```bash
devsec fix . --patch-output devsec-fix.patch

# Inspect the patch
git apply --check devsec-fix.patch

# Apply after manual review
git apply devsec-fix.patch
```

#### 8. Suppress Known Findings (.devsecignore)
To bypass a specific rule or CVE permanently:
```bash
# Suppress a specific rule on a file
echo "Dockerfile:DL3008" >> .devsecignore

# Suppress a specific CVE
echo "CVE-2024-XXXX" >> .devsecignore
```

#### 9. Native Debian Package & System Manual Pages
Build and install `devsecpac` natively on Debian/Ubuntu/Kali with system man-page integration:
```bash
# Build Debian package
./scripts/build_deb.sh

# Install system-wide
sudo dpkg -i dist/devsecpac_3.0.0_all.deb

# View manual page
man devsecpac
man devsec
```

---

### Section 2: Running via Docker Image

The official Docker image (`iamfahadshaikh/devsec-cli:latest`) packages all 16 security engines, runtimes, and dependencies into a hardened container running as unprivileged user `devsecuser` (UID: 10001).

#### 1. Check Tool Status Inside Container
```bash
docker run --rm iamfahadshaikh/devsec-cli:latest info
```

#### 2. Scan Local Workspace
Mount your host source directory into `/workspace`:
```bash
docker run --rm \
  -v "$(pwd)":/workspace \
  iamfahadshaikh/devsec-cli:latest scan .
```

#### 3. Run Fast Scan (Secrets + SAST)
```bash
docker run --rm \
  -v "$(pwd)":/workspace \
  iamfahadshaikh/devsec-cli:latest scan . -t gitleaks,semgrep,hadolint
```

#### 4. Generate Remediation Patch from Container
```bash
docker run --rm \
  -v "$(pwd)":/workspace \
  iamfahadshaikh/devsec-cli:latest fix . --patch-output devsec-fix.patch
```

#### 5. Remote Repository Scanning
Scan any remote repository without cloning it locally:
```bash
docker run --rm \
  iamfahadshaikh/devsec-cli:latest scan -r https://github.com/owner/repository.git -t semgrep,trivy
```

#### 6. Integration in CI/CD (GitHub Actions)
```yaml
name: DevSecOps Autonomous Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run DevSecPac Security Suite
        run: |
          docker run --rm -v ${{ github.workspace }}:/workspace \
            iamfahadshaikh/devsec-cli:latest scan .
```

---

## Publishing to PyPI as a Python Package

### Required Files Checklist for Python Packaging

A production-ready Python package requires:
1. `pyproject.toml` (Build system, package metadata, dependencies, and CLI entry points).
2. `README.md` (Package description, documentation, and installation guide).
3. `LICENSE` (Permissive license file, e.g. MIT).
4. `src/<package_name>/` (Clean module package structure with `__init__.py`).
5. `tests/` (Unit test suite verified with pytest).

### Publishing Procedure

#### Step 1: Install Build and Distribution Utilities
```bash
pip install --upgrade build twine
```

#### Step 2: Build Source Distribution and Wheel
Run from repository root:
```bash
python -m build
```
This generates the distribution archives inside the `dist/` directory:
- `dist/devsecpac-2.0.0.tar.gz` (Source Archive)
- `dist/devsecpac-2.0.0-py3-none-any.whl` (Built Wheel)

#### Step 3: Validate Built Packages
Run `twine check` to ensure your README format, metadata, and syntax pass PyPI requirements:
```bash
twine check dist/*
```

#### Step 4: Test Upload to TestPyPI (Recommended First Step)
Verify metadata and package rendering on TestPyPI:
```bash
twine upload --repository testpypi dist/*
```

#### Step 5: Official Production Upload to PyPI
Upload the final package to the Python Package Index:
```bash
twine upload dist/*
```
Enter your PyPI API token (`__token__` as username and your token as password) when prompted. Once complete, users can install it globally via `pip install devsecpac`.

---

## License

This project is licensed under the MIT License.
