# DevSecPac v2.0 Platform Roadmap & Architecture Specification

## 1. Overview
DevSecPac v2 elevates `devsec` from a multi-engine scanner into an autonomous DevSecOps platform with automated remediation, cross-scanner deduplication, supply-chain signing, and native CI/CD integration.

---

## 2. v2 Core Requirements & Features Status

### Pillar A: Next-Generation Security Engines
1. [x] **Semgrep (Fast SAST & Guardrails)**
   - Sub-3-second static analysis.
   - Enforce community security packs and custom company guardrails without compiling.
   - *File:* `src/devsec_cli/scanners/semgrep.py`
2. [x] **Cosign & Sigstore (Supply Chain Cryptographic Attestations)**
   - Cryptographically signs generated CycloneDX SBOMs (`sbom-cyclonedx.json`) and container images.
   - Output tamper-proof verification stamps satisfying SLSA framework level 2/3.
   - *File:* `src/devsec_cli/scanners/cosign.py`
3. [x] **OWASP ZAP (Baseline DAST Scan)**
   - Headless active DAST scanner targeting running web apps and Compose services.
   - Flags active SQLi, XSS, and missing security headers.
   - *File:* `src/devsec_cli/scanners/dast.py`
4. [x] **Schemathesis (API Contract Security Testing)**
   - Property-based API fuzzer that parses OpenAPI / Swagger / GraphQL specs to identify 500 crashes and boundary errors.
   - *File:* `src/devsec_cli/scanners/schemathesis.py`
5. [x] **Checkov & Kyverno CLI & Native Audit (Deep Kubernetes Workload Security)**
   - Static analysis of Kubernetes manifests for resource quotas, readiness probes, root privileges, and schema conformance.
   - *Files:* `src/devsec_cli/scanners/iac.py`, `src/devsec_cli/scanners/kyverno.py`, `src/devsec_cli/scanners/k8s_audit.py`
6. [x] **DefectDojo Exporter (ASPM Integration)**
   - `--defectdojo-push` flag to push consolidated results directly to enterprise vulnerability dashboards via REST API v2.
   - *Files:* `src/devsec_cli/ci.py`, `src/devsec_cli/cli.py`

---

### Pillar B: Next-Level Differentiators
1. [x] **Remediation & Patch Generation (`devsec fix`)**
   - Automatically generates suggested unified Git patches (`devsec-fix.patch`) for Dockerfile pinning and security violations.
   - *Files:* `src/devsec_cli/remediation.py`, `src/devsec_cli/cli.py`
2. [x] **Unified CVE Deduplication & Cross-Engine Correlation**
   - Correlates findings between Trivy & Dependency-Check (SCA), Gitleaks & TruffleHog (Secrets), and CodeQL & SonarQube (SAST).
   - Eliminates duplicate entries and consolidates alerts.
   - *File:* `src/devsec_cli/correlator.py`
3. [x] **CI/CD Pull-Request Commenter Mode (`devsec pr-comment`)**
   - Generates interactive, collapsible GitHub / GitLab / Azure DevOps PR comments with inline action items and badges.
   - *Files:* `src/devsec_cli/ci.py`, `src/devsec_cli/cli.py`
4. [x] **Granular Finding Suppression Engine (`.devsecignore`)**
   - Fine-grained suppression of specific file:rule pairs, CVEs, or rule IDs without altering global quality gates.
   - *File:* `src/devsec_cli/bypass.py`
5. [x] **Real-Time Telemetry & Single-Line Progress Display**
   - Single-line Rich progress bar tracking completed engines, files processed, elapsed timer, and remaining ETA.
   - *Files:* `src/devsec_cli/cli.py`, `src/devsec_cli/discovery.py`

---

## 3. Implementation Phases
- [x] **Phase 1: Deduplication & Correlation Core** (`src/devsec_cli/correlator.py`)
- [x] **Phase 2: Semgrep Fast SAST Engine Integration** (`src/devsec_cli/scanners/semgrep.py`)
- [x] **Phase 3: Schemathesis & OWASP ZAP Baseline DAST** (`src/devsec_cli/scanners/schemathesis.py`, `src/devsec_cli/scanners/dast.py`)
- [x] **Phase 4: Cosign SBOM Signing & Supply Chain Verification** (`src/devsec_cli/scanners/cosign.py`)
- [x] **Phase 5: Automated Remediation Engine (`devsec fix`)** (`src/devsec_cli/remediation.py`)
- [x] **Phase 6: CI/CD Pull-Request Commenter Mode (`devsec pr-comment`)** (`src/devsec_cli/ci.py`)
- [x] **Phase 7: DefectDojo Exporter** (`src/devsec_cli/ci.py`)
