# DevSecPac v2.0 Platform Roadmap & Architecture Specification

## 1. Overview
DevSecPac v2 elevates `devsec` from a multi-engine scanner into an autonomous DevSecOps platform with automated remediation, cross-scanner deduplication, supply-chain signing, and native CI/CD integration.

---

## 2. v2 Core Requirements & Features

### Pillar A: Next-Generation Security Engines
1. **Semgrep (Fast SAST & Guardrails)**
   - Sub-3-second static analysis.
   - Enforce community security packs and custom company guardrails without compiling.
2. **Cosign & Sigstore (Supply Chain Cryptographic Attestations)**
   - Cryptographically sign generated CycloneDX SBOMs (`sbom-cyclonedx.json`) and container images.
   - Output tamper-proof verification stamps satisfying SLSA framework level 2/3.
3. **OWASP ZAP (Baseline DAST Scan)**
   - Headless active DAST scanner (`zap-baseline.py`) targeting running web apps / Compose services.
   - Flags active SQLi, XSS, and missing security headers.
4. **Schemathesis (API Contract Security Testing)**
   - Property-based API fuzzer that parses OpenAPI / Swagger / GraphQL specs to identify 500 crashes and boundary errors.
5. **Polaris / Checkov K8s Security (Deep Kubernetes Workload Security)**
   - Static analysis of Kubernetes manifests for resource quotas, readiness probes, and root privileges.
6. **DefectDojo & Faraday Exporters (ASPM Integration)**
   - `--defectdojo-push` flag to push consolidated results directly to enterprise vulnerability dashboards via REST API.

---

### Pillar B: Next-Level Differentiators
1. **Automated AI Remediation & Patch Generation (`devsec fix`)**
   - Automatically generates unified Git patches (`devsec-fix.patch`) or fixes lockfiles and Dockerfile best practice violations.
2. **Unified CVE Deduplication & Cross-Engine Correlation**
   - Correlates findings between Trivy & Dependency-Check (SCA), Gitleaks & TruffleHog (Secrets), and CodeQL & SonarQube (SAST).
   - Eliminates duplicate entries and provides consolidated risk-confidence scores.
3. **CI/CD Pull-Request Commenter Mode (`devsec ci --pr`)**
   - Generates interactive, collapsible GitHub / GitLab / Azure DevOps PR comments with inline code annotations.

---

## 3. Implementation Phases
- [ ] **Phase 1: Deduplication & Correlation Core** (`src/devsec_cli/correlator.py`)
- [x] **Phase 2: Semgrep Fast SAST Engine Integration**
- [ ] **Phase 3: Schemathesis & OWASP ZAP Baseline DAST**
- [ ] **Phase 4: Cosign SBOM Signing & Supply Chain Verification**
- [ ] **Phase 5: Automated Remediation Engine (`devsec fix`)**
- [ ] **Phase 6: CI/CD Pull-Request Commenter Mode (`devsec ci --pr`)**
- [ ] **Phase 7: DefectDojo Exporter**
