"""Advanced Knowledge Base (AKB) loader tests."""

from __future__ import annotations

from aqc.akb import AKB, append_compliance_tail, knowledge_base_root
from aqc.cbom_generator import scan_assets
from aqc.hndl_analyzer import HNDLAnalyzer, synthetic_samples


def test_knowledge_base_root_prefers_bundled_package() -> None:
    root = knowledge_base_root()
    assert (root / "bio_cyber_ontology" / "neural_threats.yaml").is_file()
    assert (root / "threat_profiles" / "slater_hndl_2026.yaml").is_file()


def test_akb_loads_thresholds() -> None:
    akb = AKB.load()
    assert akb.neural.entropy_floor_bits_per_byte == 7.2
    assert akb.neural.rate_floor_hz == 200.0
    assert akb.neural.latency_ceiling_ms == 25.0
    assert akb.cardiac.latency_threshold_ms == 8.0
    assert akb.slater.profile_id == "slater_hndl_2026"
    assert append_compliance_tail("x", "cbom.classical_asymmetric_on_cognitive", akb) != "x"


def test_hndl_analyzer_uses_akb() -> None:
    assets = scan_assets(seed=2)
    samples = synthetic_samples(assets, seed=2)
    ana = HNDLAnalyzer(knowledge_root=knowledge_base_root())
    assert ana.threat_profile_id == "slater_hndl_2026"
    findings = ana.analyze(samples)
    assert findings
