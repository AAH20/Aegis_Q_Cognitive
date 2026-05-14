"""JADC2 Quantum-Resistant Identity-First Segmentation engine.

Given a list of HNDL findings (and/or a CBOM), this module proposes a
Layer-3 microsegmentation policy that isolates vulnerable BCI and
biometric endpoints from the broader Joint All-Domain Command and
Control (JADC2) tactical mesh until each device can be wrapped in an
ML-KEM key exchange tunnel signed by ML-DSA.

The policy follows three principles:

1. **Identity-First** – every endpoint gets a workload identity (SPIFFE
   ID) signed by an ML-DSA CA, not an IP / MAC binding.
2. **Deny-by-Default** – the tactical fabric only forwards packets
   between identities that hold an explicit allow rule.
3. **Quantum-Safe Layer-3** – data-plane tunnels are established with
   hybrid ML-KEM-768 + X25519, signed transcripts use ML-DSA-65, and
   long-term anchors use SLH-DSA.

The output is a dictionary; the CLI renders it as YAML-ish text. We
deliberately avoid pyyaml so the dependency footprint stays tiny.
"""

from __future__ import annotations

from typing import Iterable, Optional

try:  # Optional — only used to build a richer enclave graph.
    import networkx as nx  # type: ignore[import-untyped]

    _HAS_NX = True
except Exception:  # pragma: no cover
    nx = None  # type: ignore[assignment]
    _HAS_NX = False

from ._models import (
    CryptoAsset,
    DeviceClass,
    HNDLFinding,
    SegmentationPolicy,
    Severity,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PQC_KEX_DEFAULT: str = "ML-KEM-768 + X25519 (hybrid)"
PQC_SIG_DEFAULT: str = "ML-DSA-65"
PQC_ROOT_SIG: str = "SLH-DSA-SHA2-128s"

# Tactical fabrics that should never see cognitive-class telemetry
# without a PQC tunnel.
TACTICAL_PEERS: tuple[str, ...] = (
    "jadc2-c2-fabric",
    "abms-cloud-one",
    "navy-pmw-160",
    "army-pc-c3t",
    "spaceforce-warpcore",
)

# Map a device class to the enclave it belongs in. Identity-first means
# enclaves are *roles*, not subnets.
_ENCLAVE_FOR: dict[DeviceClass, str] = {
    DeviceClass.BCI: "cognitive-bci-enclave",
    DeviceClass.EEG_WEARABLE: "cognitive-eeg-enclave",
    DeviceClass.MEDTECH_IMPLANT: "medtech-implant-enclave",
    DeviceClass.BIOMETRIC_RING: "biometric-wearable-enclave",
    DeviceClass.SMART_WATCH: "biometric-wearable-enclave",
    DeviceClass.JADC2_RADIO: "jadc2-tactical-enclave",
    DeviceClass.UNKNOWN: "quarantine-enclave",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_vulnerable(severity: Severity) -> bool:
    return severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def _endpoints_by_enclave(
    findings: Iterable[HNDLFinding],
) -> dict[str, list[HNDLFinding]]:
    bucket: dict[str, list[HNDLFinding]] = {}
    for finding in findings:
        enclave = _ENCLAVE_FOR.get(finding.device_class, "quarantine-enclave")
        bucket.setdefault(enclave, []).append(finding)
    return bucket


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def propose_remediation(
    findings: Iterable[HNDLFinding],
    *,
    pqc_kex: str = PQC_KEX_DEFAULT,
    pqc_sig: str = PQC_SIG_DEFAULT,
) -> list[SegmentationPolicy]:
    """Return one :class:`SegmentationPolicy` per affected enclave.

    Endpoints that are already CNSA 2.0 compliant (``Severity.SAFE``) are
    allowed to peer directly with the JADC2 tactical fabric. Everything
    else is quarantined until a PQC tunnel is up.
    """

    grouped = _endpoints_by_enclave(findings)
    policies: list[SegmentationPolicy] = []

    for enclave, group in sorted(grouped.items()):
        vulnerable = [f for f in group if _is_vulnerable(f.severity)]
        safe = [f for f in group if f.severity is Severity.SAFE]

        if vulnerable:
            policies.append(
                SegmentationPolicy(
                    enclave_name=enclave,
                    isolated_endpoints=sorted({f.endpoint for f in vulnerable}),
                    allowed_peers=["aqc-pqc-gateway"],
                    pqc_kex=pqc_kex,
                    pqc_sig=pqc_sig,
                    deny_by_default=True,
                    require_mtls_pqc=True,
                    notes=(
                        "Endpoints are isolated from the JADC2 tactical "
                        "fabric. Egress only via the AQC PQC gateway, "
                        "which terminates legacy TLS and re-wraps the "
                        "stream in a hybrid "
                        f"{pqc_kex} tunnel signed by {pqc_sig}."
                    ),
                )
            )
        if safe:
            policies.append(
                SegmentationPolicy(
                    enclave_name=f"{enclave}::pqc-compliant",
                    isolated_endpoints=sorted({f.endpoint for f in safe}),
                    allowed_peers=list(TACTICAL_PEERS),
                    pqc_kex=pqc_kex,
                    pqc_sig=pqc_sig,
                    deny_by_default=True,
                    require_mtls_pqc=True,
                    notes=(
                        "PQC-compliant endpoints are admitted to the "
                        "tactical fabric under identity-first mTLS."
                    ),
                )
            )
    return policies


def build_topology(
    assets: Iterable[CryptoAsset],
    findings: Iterable[HNDLFinding],
):  # -> nx.MultiDiGraph | None
    """Return a topology graph (or ``None`` if networkx is missing)."""

    if not _HAS_NX or nx is None:
        return None
    g = nx.MultiDiGraph()
    g.add_node("aqc-pqc-gateway", kind="gateway", quantum_safe=True)
    for peer in TACTICAL_PEERS:
        g.add_node(peer, kind="tactical-fabric", quantum_safe=True)
        g.add_edge("aqc-pqc-gateway", peer, channel=PQC_KEX_DEFAULT)

    findings_by_endpoint = {f.endpoint: f for f in findings}
    for asset in assets:
        finding = findings_by_endpoint.get(asset.endpoint)
        quantum_safe = (
            finding is not None and finding.severity is Severity.SAFE
        ) or asset.severity is Severity.SAFE
        g.add_node(
            asset.endpoint,
            kind=asset.device_class.value,
            algorithm=asset.algorithm,
            quantum_safe=quantum_safe,
            severity=asset.severity.value,
        )
        if quantum_safe:
            for peer in TACTICAL_PEERS:
                g.add_edge(asset.endpoint, peer, channel=PQC_KEX_DEFAULT)
        else:
            g.add_edge(
                asset.endpoint, "aqc-pqc-gateway", channel=asset.algorithm
            )
    return g


def render_policy(policies: list[SegmentationPolicy]) -> str:
    """Render policies as a deterministic YAML-like string (no pyyaml)."""

    lines: list[str] = [
        "# Aegis Quantum-Cognitive — JADC2 Identity-First Segmentation",
        "apiVersion: aqc.defense/v1",
        "kind: QuantumSafeSegmentationPolicy",
        f"root_signature: {PQC_ROOT_SIG}",
        "spec:",
        "  default_action: deny",
        "  identity: spiffe://aqc.mil/<enclave>/<workload>",
        "  enclaves:",
    ]
    for pol in policies:
        lines.append(f"    - name: {pol.enclave_name}")
        lines.append(f"      pqc_kex: {pol.pqc_kex}")
        lines.append(f"      pqc_sig: {pol.pqc_sig}")
        lines.append(f"      deny_by_default: {str(pol.deny_by_default).lower()}")
        lines.append(f"      require_mtls_pqc: {str(pol.require_mtls_pqc).lower()}")
        lines.append("      isolated_endpoints:")
        for ep in pol.isolated_endpoints:
            lines.append(f"        - {ep}")
        lines.append("      allowed_peers:")
        for peer in pol.allowed_peers:
            lines.append(f"        - {peer}")
        lines.append(f"      notes: |")
        for note_line in pol.notes.splitlines() or [pol.notes]:
            lines.append(f"        {note_line}")
    return "\n".join(lines) + "\n"


def remediation_summary(policies: list[SegmentationPolicy]) -> dict[str, int]:
    """Quick stats for the CLI footer."""

    isolated = sum(len(p.isolated_endpoints) for p in policies if p.deny_by_default)
    enclaves = len(policies)
    pqc_compliant = sum(
        len(p.isolated_endpoints)
        for p in policies
        if p.enclave_name.endswith("::pqc-compliant")
    )
    return {
        "enclaves": enclaves,
        "endpoints_isolated": isolated - pqc_compliant,
        "endpoints_pqc_compliant": pqc_compliant,
    }
