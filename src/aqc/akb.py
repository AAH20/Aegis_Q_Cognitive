"""Advanced Knowledge Base (AKB) — load bio-cyber ontology + threat profiles.

Machine-readable YAML under ``knowledge_base/`` supplies thresholds and
regulatory cross-walks so analyzers are not a pile of unexplained floats.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "AKB requires PyYAML. Install with: pip install pyyaml"
    ) from e


def knowledge_base_root(explicit: Path | None = None) -> Path:
    """Resolve the ``knowledge_base/`` directory."""

    if explicit is not None:
        return explicit.resolve()
    env = os.environ.get("AQC_KNOWLEDGE_BASE")
    if env:
        return Path(env).expanduser().resolve()
    cwd = Path.cwd() / "knowledge_base"
    if cwd.is_dir():
        return cwd.resolve()
    here = Path(__file__).resolve()
    repo = here.parents[2] / "knowledge_base"
    if repo.is_dir():
        return repo.resolve()
    pkg = here.parent / "knowledge_base"
    if pkg.is_dir():
        return pkg.resolve()
    raise FileNotFoundError(
        "knowledge_base not found. Set AQC_KNOWLEDGE_BASE or run from repo with KB present."
    )


@dataclass
class NeuralFingerprint:
    entropy_floor_bits_per_byte: float
    rate_floor_hz: float
    latency_ceiling_ms: float


@dataclass
class CardiacTiming:
    latency_threshold_ms: float
    vulnerable_phase: str
    narrative_anchor: str


@dataclass
class SlaterProfile:
    profile_id: str
    q_day_year: int
    targeted_algorithms: list[str]
    collection_priority: list[str]


@dataclass
class ComplianceMappings:
    raw: dict[str, Any]
    rule_links: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AKB:
    root: Path
    neural: NeuralFingerprint
    cardiac: CardiacTiming
    slater: SlaterProfile
    compliance: ComplianceMappings

    @classmethod
    def load(cls, root: Path | None = None) -> AKB:
        kb = knowledge_base_root(root)

        cardiac_path = kb / "bio_cyber_ontology" / "cardiac_threats.yaml"
        neural_path = kb / "bio_cyber_ontology" / "neural_threats.yaml"
        slater_path = kb / "threat_profiles" / "slater_hndl_2026.yaml"
        comp_path = kb / "compliance_mappings" / "nsm10_cnsa2.yaml"

        for p in (cardiac_path, neural_path, slater_path, comp_path):
            if not p.is_file():
                raise FileNotFoundError(f"AKB file missing: {p}")

        with cardiac_path.open(encoding="utf-8") as f:
            cardiac_doc = yaml.safe_load(f)
        with neural_path.open(encoding="utf-8") as f:
            neural_doc = yaml.safe_load(f)
        with slater_path.open(encoding="utf-8") as f:
            slater_doc = yaml.safe_load(f)
        with comp_path.open(encoding="utf-8") as f:
            comp_doc = yaml.safe_load(f)

        if not isinstance(cardiac_doc, dict):
            raise ValueError("cardiac_threats.yaml must be a mapping")
        if not isinstance(neural_doc, dict):
            raise ValueError("neural_threats.yaml must be a mapping")
        if not isinstance(slater_doc, dict):
            raise ValueError("slater profile yaml must be a mapping")
        if not isinstance(comp_doc, dict):
            raise ValueError("compliance mapping yaml must be a mapping")

        ct = cardiac_doc.get("cardiac_exploit_timing", {})
        sc = neural_doc.get("soul_catcher_2_0", {})
        fp = sc.get("hndl_stream_fingerprint", {})
        if not isinstance(fp, dict):
            raise ValueError("neural_threats: missing hndl_stream_fingerprint")

        overrides = slater_doc.get("hndl_classifier_overrides") or {}
        ef_key = "entropy_ciphertext_floor_bits_per_byte"
        rf_key = "neural_packet_rate_floor_hz"
        la_key = "median_inter_arrival_ceiling_ms"
        entropy = float(overrides.get(ef_key, fp[ef_key]))
        rate = float(overrides.get(rf_key, fp[rf_key]))
        lat = float(overrides.get(la_key, fp[la_key]))

        cardiac = CardiacTiming(
            latency_threshold_ms=float(ct.get("latency_threshold_ms", 8.0)),
            vulnerable_phase=str(ct.get("vulnerable_phase", "")),
            narrative_anchor=str(ct.get("narrative_anchor", "")),
        )
        neural = NeuralFingerprint(
            entropy_floor_bits_per_byte=entropy,
            rate_floor_hz=rate,
            latency_ceiling_ms=lat,
        )
        meta = slater_doc.get("meta", {})
        slater = SlaterProfile(
            profile_id=str(meta.get("profile_id", "slater_hndl_2026")),
            q_day_year=int(slater_doc.get("q_day_estimation_year", 2030)),
            targeted_algorithms=list(slater_doc.get("targeted_algorithms", [])),
            collection_priority=list(slater_doc.get("collection_priority", [])),
        )
        comp = ComplianceMappings(
            raw=comp_doc,
            rule_links=list(comp_doc.get("aqc_rule_links", [])),
        )
        return cls(
            root=kb,
            neural=neural,
            cardiac=cardiac,
            slater=slater,
            compliance=comp,
        )


def append_compliance_tail(rationale: str, rule_id: str, akb: AKB | None) -> str:
    """Append a short regulatory trace from the mapping matrix."""

    if akb is None:
        return rationale
    extra = ""
    for link in akb.compliance.rule_links:
        if link.get("rule_id") == rule_id:
            inv = link.get("investor_phrase")
            if inv:
                extra = f" [AKB: {inv}]"
            break
    return f"{rationale}{extra}"
