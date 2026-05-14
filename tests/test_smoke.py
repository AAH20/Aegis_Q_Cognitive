"""Lightweight smoke tests for the AQC pipeline.

These tests deliberately avoid any heavy dependency (scapy, liboqs) so
they can run on a stock Python 3.11 install with only click + rich.
"""

from __future__ import annotations

from aqc._models import Severity
from aqc.cbom_generator import generate_cbom, scan_assets, summarise
from aqc.hndl_analyzer import HNDLAnalyzer, synthetic_samples
from aqc.jadc2_segmentation import (
    propose_remediation,
    remediation_summary,
    render_policy,
)


def test_scan_assets_returns_mixed_severity_fleet() -> None:
    assets = scan_assets(seed=1)
    severities = {a.severity for a in assets}
    assert Severity.CRITICAL in severities, "expected at least one CRITICAL asset"
    assert Severity.SAFE in severities, "expected at least one PQC-SAFE asset"


def test_cbom_is_cyclonedx_shaped() -> None:
    assets = scan_assets(seed=1)
    cbom = generate_cbom(assets, target="unit-test-fleet")
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["components"], "CBOM must have at least one component"
    histogram = summarise(assets)
    assert sum(histogram.values()) == len(assets)


def test_hndl_flags_soul_catcher_vector() -> None:
    assets = scan_assets(seed=1)
    samples = synthetic_samples(assets, seed=1)
    findings = HNDLAnalyzer().analyze(samples)
    assert any(
        f.soul_catcher_vector and f.severity is Severity.CRITICAL
        for f in findings
    ), "expected at least one Soul Catcher 2.0 critical finding"


def test_remediation_isolates_vulnerable_endpoints() -> None:
    assets = scan_assets(seed=1)
    samples = synthetic_samples(assets, seed=1)
    findings = HNDLAnalyzer().analyze(samples)
    policies = propose_remediation(findings)
    assert policies, "expected at least one segmentation policy"
    rendered = render_policy(policies)
    assert "QuantumSafeSegmentationPolicy" in rendered
    stats = remediation_summary(policies)
    assert stats["endpoints_isolated"] >= 1
