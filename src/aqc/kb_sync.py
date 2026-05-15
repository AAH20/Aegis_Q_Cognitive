"""Simulated knowledge-base update (SaaS bundle) — local manifest only.

Production systems would verify signed artifacts from an update
infrastructure. This module proves the *integration point* without
calling the public Internet.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .akb import knowledge_base_root


def simulate_cloud_sync(knowledge_root: Path | None = None) -> Path:
    """Write a manifest proving the sync hook; no remote fetch."""

    root = knowledge_base_root(knowledge_root)
    manifest = {
        "sync_mode": "simulated",
        "updated_at": datetime.now(UTC).isoformat(),
        "message": (
            "Production AQC deployments would fetch cryptographically signed "
            "ontology / compliance-mapping bundles from customer-controlled "
            "update infrastructure (air-gap compatible)."
        ),
        "artifacts_expected": [
            "bio_cyber_ontology/cardiac_threats.yaml",
            "bio_cyber_ontology/neural_threats.yaml",
            "threat_profiles/slater_hndl_2026.yaml",
            "compliance_mappings/nsm10_cnsa2.yaml",
        ],
    }
    out = root / ".sync_manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return root
