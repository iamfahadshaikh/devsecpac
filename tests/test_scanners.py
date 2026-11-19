"""Unit tests for devsec-cli core functionality."""

import json
from pathlib import Path
from devsec_cli.discovery import TargetDiscovery
from devsec_cli.contracts import ToolResult, StatusEnum, FindingCounts
from devsec_cli.scanners.k8s_audit import K8sStructuralAuditScanner
from devsec_cli.reporter import Reporter


def test_contracts_json_serialization():
    result = ToolResult(
        tool_name="TestTool",
        category="TestCat",
        status=StatusEnum.PASS,
        summary="All clear",
        findings=FindingCounts(critical=0, high=0, medium=1, low=2, info=0)
    )
    json_str = result.to_json()
    data = json.loads(json_str)
    assert data["tool_name"] == "TestTool"
    assert data["status"] == "PASS"
    assert data["findings"]["medium"] == 1


def test_k8s_structural_audit_catches_violations(tmp_path: Path):
    bad_manifest = tmp_path / "deployment.yaml"
    bad_manifest.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-deployment
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: host-mount
          hostPath:
            path: /etc
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
            runAsUser: 0
    """, encoding="utf-8")

    scanner = K8sStructuralAuditScanner()
    res = scanner.scan(tmp_path)

    assert res.status == StatusEnum.FAIL
    assert res.findings.critical >= 2  # privileged + hostPath
    assert res.findings.high >= 2      # hostNetwork + runAsUser: 0


def test_markdown_summary_generation(tmp_path: Path):
    out_md = tmp_path / "summary.md"
    results = [
        ToolResult(
            tool_name="Gitleaks",
            category="Secret Detection",
            status=StatusEnum.PASS,
            summary="Clean",
            findings=FindingCounts()
        )
    ]
    reporter = Reporter()
    reporter.generate_markdown_summary(results, out_md)

    content = out_md.read_text(encoding="utf-8")
    assert "Autonomous DevSecOps Pipeline Security Report" in content
    assert "GATE PASSED" in content
