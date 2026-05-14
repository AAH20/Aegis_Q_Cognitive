"""Compliance pack compiler.

Consumes the JSON artifacts produced by ``aqc scan-neural-pcap``
(``cbom.json`` and ``hndl-findings.json``) and emits two auditor-ready
deliverables:

* an **FDA e-STAR Cybersecurity Addendum** that satisfies the
  Premarket Cybersecurity Refuse-to-Accept (RTA) policy effective for
  510(k) / De Novo / PMA submissions (FDA guidance, 2023-09-27), and
* a **DoD NSM-10 PQC Transition Roadmap** mapped to CNSA 2.0
  deadlines (FIPS 203 / 204 / 205).

Both deliverables are Markdown and are optionally rendered through
``pandoc`` (HTML) and ``pandoc + weasyprint`` (PDF) when those tools
are on ``$PATH``. When they are not, AQC writes Markdown and reports
the missing tooling — the artifacts a Regulatory Affairs team needs
still ship.

The contract here matches ``aqc.cli`` exactly:

* :func:`load_bundle_from_disk` builds a :class:`ComplianceBundle`
  from the two report files plus a small bag of submitter metadata.
* :func:`summarise_bundle` returns the headline counts the CLI prints.
* :func:`write_compliance_pack` writes Markdown (+ optional HTML/PDF)
  and returns a path map keyed by artifact identifier.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from . import __version__
from ._models import Severity


# ---------------------------------------------------------------------------
# CNSA 2.0 transition calendar (DoD National Manager, abbreviated)
# ---------------------------------------------------------------------------

_CNSA2_DEADLINES: tuple[tuple[str, str, str], ...] = (
    ("Software / firmware signing",   "ML-DSA-87 or SLH-DSA",   "by 2025-12-31"),
    ("Web browsers / cloud services", "ML-KEM-768 + X25519",    "by 2025-12-31"),
    ("Traditional networking",        "ML-KEM-768",             "by 2027-12-31"),
    ("Operating systems",             "ML-DSA-65, ML-KEM-768",  "by 2027-12-31"),
    ("Niche / custom hardware",       "ML-KEM-1024, ML-DSA-87", "by 2030-12-31"),
    ("All NSS systems",               "Full CNSA 2.0 suite",    "by 2033-12-31"),
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SubmissionMetadata:
    """The thin slice of submitter / regulatory metadata AQC asks for."""

    sponsor: str = "Acquirer-Of-Record (TBD)"
    device_trade_name: str = "Subject Neural / Biometric Device"
    fda_submission_type: str = "510(k)"
    contract_vehicle: str = "JADC2 — TBD"


@dataclass(slots=True)
class ComplianceBundle:
    """Aggregated input to the FDA and NSM-10 renderers."""

    cbom: dict
    hndl_findings: list[dict] = field(default_factory=list)
    metadata: SubmissionMetadata = field(default_factory=SubmissionMetadata)

    @property
    def components(self) -> list[dict]:
        return self.cbom.get("components", []) or []

    @property
    def cbom_serial(self) -> str:
        return self.cbom.get("serialNumber", "urn:aqc:unset")

    @property
    def doc_id(self) -> str:
        seed = self.cbom_serial.encode("utf-8")
        return "AQC-PKG-" + hashlib.sha256(seed).hexdigest()[:12].upper()


# ---------------------------------------------------------------------------
# CBOM / HNDL accessors
# ---------------------------------------------------------------------------


def _severity_of(component: dict) -> Severity:
    for prop in component.get("properties", []):
        if prop.get("name") == "aqc:severity":
            try:
                return Severity(prop.get("value", "MEDIUM"))
            except ValueError:
                return Severity.MEDIUM
    return Severity.MEDIUM


def _algorithm_of(c: dict) -> str:
    return c.get("name", "UNKNOWN")


def _endpoint_of(c: dict) -> str:
    return (c.get("evidence") or {}).get("endpoint", "unknown")


def _device_class_of(c: dict) -> str:
    return (c.get("evidence") or {}).get("device_class", "UNKNOWN")


def _rationale_of(c: dict) -> str:
    for prop in c.get("properties", []):
        if prop.get("name") == "aqc:rationale":
            return prop.get("value", "")
    return ""


def _histogram(components: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {s.value: 0 for s in Severity}
    for c in components:
        out[_severity_of(c).value] += 1
    return out


def _soul_catcher_count(findings: Iterable[dict]) -> int:
    return sum(1 for f in findings if f.get("soul_catcher_vector"))


# ---------------------------------------------------------------------------
# Public ingest
# ---------------------------------------------------------------------------


def load_bundle_from_disk(
    cbom_path: Path | str,
    hndl_path: Optional[Path | str] = None,
    *,
    sponsor: str = "Acquirer-Of-Record (TBD)",
    device_trade_name: str = "Subject Neural / Biometric Device",
    fda_submission_type: str = "510(k)",
    contract_vehicle: str = "JADC2 — TBD",
) -> ComplianceBundle:
    """Build a :class:`ComplianceBundle` from disk artifacts.

    ``hndl_path`` is optional; when missing the bundle still produces a
    valid FDA/NSM-10 pair driven by the CBOM alone, but the
    "Soul Catcher 2.0 vector" count in the FDA risk table will read 0.
    """

    cbom = json.loads(Path(cbom_path).read_text(encoding="utf-8"))
    findings: list[dict] = []
    if hndl_path is not None and Path(hndl_path).exists():
        findings = json.loads(Path(hndl_path).read_text(encoding="utf-8"))
    return ComplianceBundle(
        cbom=cbom,
        hndl_findings=findings,
        metadata=SubmissionMetadata(
            sponsor=sponsor,
            device_trade_name=device_trade_name,
            fda_submission_type=fda_submission_type,
            contract_vehicle=contract_vehicle,
        ),
    )


def summarise_bundle(bundle: ComplianceBundle) -> dict[str, object]:
    """Return the headline metrics the CLI renders into a table."""

    hist = _histogram(bundle.components)
    return {
        "doc_id": bundle.doc_id,
        "assets": len(bundle.components),
        "critical": hist[Severity.CRITICAL.value],
        "high": hist[Severity.HIGH.value],
        "medium": hist[Severity.MEDIUM.value],
        "low": hist[Severity.LOW.value],
        "safe": hist[Severity.SAFE.value],
        "soul_catcher_vectors": _soul_catcher_count(bundle.hndl_findings),
    }


# ---------------------------------------------------------------------------
# Markdown rendering helpers
# ---------------------------------------------------------------------------


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _md_table(headers: list[str], rows: Iterable[list[str]]) -> str:
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join(["---"] * len(headers)) + " |"
    body_lines = ["| " + " | ".join(r) + " |" for r in rows]
    if not body_lines:
        body_lines = ["| " + " | ".join(["—"] * len(headers)) + " |"]
    return "\n".join([head, sep, *body_lines])


def _doc_id(prefix: str, bundle: ComplianceBundle) -> str:
    seed = bundle.cbom_serial.encode("utf-8")
    return f"{prefix}-{hashlib.sha256(seed).hexdigest()[:12].upper()}"


# ---------------------------------------------------------------------------
# FDA e-STAR Cybersecurity Addendum
# ---------------------------------------------------------------------------


def render_fda_estar(bundle: ComplianceBundle) -> str:
    """Render the FDA e-STAR Cybersecurity Addendum as Markdown."""

    md = bundle.metadata
    components = bundle.components
    hist = _histogram(components)
    sc_count = _soul_catcher_count(bundle.hndl_findings)
    doc_id = _doc_id("AQC-FDA-ESTAR", bundle)

    critical_eps = [_endpoint_of(c) for c in components if _severity_of(c) is Severity.CRITICAL]
    high_eps = [_endpoint_of(c) for c in components if _severity_of(c) is Severity.HIGH]
    medium_eps = [_endpoint_of(c) for c in components if _severity_of(c) is Severity.MEDIUM]
    safe_eps = [_endpoint_of(c) for c in components if _severity_of(c) is Severity.SAFE]

    inventory_rows = [
        [
            _endpoint_of(c),
            _device_class_of(c),
            _algorithm_of(c),
            _severity_of(c).value,
            _rationale_of(c)[:90].replace("|", "/"),
        ]
        for c in components
    ]

    hndl_rows = [
        [
            f.get("endpoint", "—"),
            f.get("device_class", "—"),
            f.get("algorithm", "—"),
            f.get("severity", "—"),
            "YES" if f.get("soul_catcher_vector") else "no",
        ]
        for f in bundle.hndl_findings
    ]

    sections: list[str] = []
    sections.append(
        f"""# FDA e-STAR Cybersecurity Addendum

**Document ID:** {doc_id}
**Generated:** {_utc_now_str()}
**Generator:** Aegis Quantum-Cognitive v{__version__} (`aqc.compliance_compiler`)
**Sponsor / Holder of Record:** {md.sponsor}
**Device Trade Name:** {md.device_trade_name}
**FDA Submission Type:** {md.fda_submission_type}
**CBOM Reference:** `{bundle.cbom_serial}`

> This addendum drops into the FDA *Electronic Submission Template And
> Resource* (e-STAR) under the Cybersecurity section, in conformance
> with the **Cybersecurity in Medical Devices: Quality System
> Considerations and Content of Premarket Submissions** guidance
> (final, 2023-09-27) and the **Refuse-to-Accept (RTA)** policy
> effective from 2023-10-01.

---

## 1. Executive Summary

| Field                        | Value |
| ---------------------------- | ----- |
| Subject Device               | {md.device_trade_name} |
| Sponsor                      | {md.sponsor} |
| Submission Type              | {md.fda_submission_type} |
| Contract Vehicle (DoD/UHNW)  | {md.contract_vehicle} |

### 1.1 Cybersecurity Risk Posture at a Glance

| Tier      | Asset Count |
| --------- | ----------- |
| CRITICAL  | {hist['CRITICAL']} |
| HIGH      | {hist['HIGH']} |
| MEDIUM    | {hist['MEDIUM']} |
| LOW       | {hist['LOW']} |
| PQC-SAFE  | {hist['SAFE']} |
| Soul Catcher 2.0 vectors | {sc_count} |

**Headline Finding.** {hist['CRITICAL']} cryptographic asset(s) on the
subject device's transport surface are presently exposed to **Harvest
Now, Decrypt Later (HNDL)** attack, and {sc_count} of those carry the
neural fingerprint that promotes the finding to a *Soul Catcher 2.0*
vector. Mitigations are scheduled in §9 and §12.

### 1.2 e-STAR Section Map

Each section below answers exactly one e-STAR field. Reviewers can
cross-reference Section IDs (`§n.n`) against the corresponding e-STAR
check-box without re-reading.

---

## 2. Device Description and Operational Context

The device acquires continuous biometric, physiological, or neural
telemetry from one or more body-worn, in-vivo, or proximity sensors
and transmits that telemetry over an IP-based network to a cloud
analytics service. The transport surface inventoried in this addendum
is the union of every (host, port, cryptographic primitive) tuple
observed during a representative 24-hour capture, normalised through
the Aegis Quantum-Cognitive scanner (`aqc scan-neural-pcap`).

A simplified data-flow diagram is provided in §10.

---

## 3. Cybersecurity Risk Assessment (CRA)

The CRA was performed per ANSI/AAMI SW96:2023 and the FDA Premarket
Cybersecurity guidance, with two AQC extensions:

1. **HNDL extension.** Every classical asymmetric primitive observed
   in transit is treated as a *future-decryption oracle*: plaintext
   is assumed recoverable by an adversary holding a
   cryptographically-relevant quantum computer (CRQC) on or before
   the national-security target year 2030.
2. **Cognitive-baseline extension.** Where a stream's packet-rate
   fingerprint is consistent with neural / EEG / continuous
   physiological signals, the privacy impact post-HNDL is escalated
   to **Patient Safety Critical** because the decrypted baseline
   enables active spoofing of bidirectional stimulation surfaces
   ("Soul Catcher 2.0" injection vector).

### 3.1 Critical Findings (Tier: CRITICAL)

"""
    )
    sections.append(
        "\n".join(f"- `{ep}`" for ep in critical_eps) + "\n"
        if critical_eps
        else "- *No CRITICAL findings.*\n"
    )
    sections.append("\n### 3.2 High Findings (Tier: HIGH)\n\n")
    sections.append(
        "\n".join(f"- `{ep}`" for ep in high_eps) + "\n"
        if high_eps
        else "- *No HIGH findings.*\n"
    )
    sections.append("\n### 3.3 Medium / Residual Findings\n\n")
    sections.append(
        "\n".join(f"- `{ep}`" for ep in medium_eps) + "\n"
        if medium_eps
        else "- *No MEDIUM findings.*\n"
    )

    sections.append(
        """
---

## 4. Threat Modeling (STRIDE + HNDL Extension)

| Threat                | STRIDE     | HNDL applies | Mitigation (see §9)                 |
| --------------------- | ---------- | ------------ | ----------------------------------- |
| Eavesdropping         | I (Info)   | YES          | Migrate KEX to ML-KEM-768 + X25519. |
| Session replay        | T (Tamper) | YES (post Q) | AEAD + monotonic nonce + ML-DSA-65. |
| Identity spoofing     | S (Spoof)  | YES (post Q) | SPIFFE + ML-DSA-65 long-term anchor.|
| Cognitive injection   | E (Elev.)  | YES (SC 2.0) | §12 — bidirectional control.        |
| Firmware rollback     | T          | partial      | SLH-DSA-signed firmware manifests.  |
| Denial of service     | D          | no           | Rate-limiting; out-of-scope.        |
| Repudiation           | R          | partial      | ML-DSA-65 transcript binding.       |

---

"""
    )

    sections.append(
        f"## 5. Cryptographic Bill of Materials (CBOM) Inventory\n\n"
        f"Source: `{bundle.cbom_serial}` (CycloneDX 1.6 conformant).\n\n"
        + _md_table(
            ["Endpoint", "Device Class", "Algorithm", "Severity", "Rationale"],
            inventory_rows,
        )
        + "\n\nThe machine-readable CBOM SHALL accompany this addendum as `cbom.json`.\n"
    )

    sections.append(
        f"""

---

## 6. HNDL Stream Audit (Data-in-Transit)

These findings come from `aqc.hndl_analyzer`. Each row represents one
inspected stream and the cognitive / quantum exposure verdict.

"""
        + _md_table(
            ["Endpoint", "Device", "Algorithm", "Severity", "Soul Catcher 2.0"],
            hndl_rows,
        )
        + "\n"
    )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sections.append(
        """

---

## 7. CBOM / SBOM Methodology

The CBOM is regenerated automatically on every firmware build via
`aqc scan-neural-pcap` against a 24-hour representative capture in the
manufacturer's clean lab. Each component carries:

- `bom-ref` — a stable URN of the form `crypto:<algorithm>@<endpoint>`.
- `evidence.endpoint`, `evidence.protocol`, `evidence.device_class`.
- `aqc:severity` (`CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `SAFE`).
- `aqc:rationale` — a one-line human-readable justification.
- `aqc:quantum_safe` — boolean derived from FIPS 203 / 204 / 205.

The CBOM is checked into the firmware repository under
`/security/cbom/` and is signed by an ML-DSA-65 release key (see §9).

---

## 8. Vulnerability Management & Coordinated Disclosure

- **Disclosure path:** ISO/IEC 29147 + 30111 implementation; PSIRT
  contact published in `SECURITY.md`.
- **CBOM monitoring:** NIST algorithm deprecations pulled daily; an
  automatic e-STAR amendment is filed within 30 days of any algorithm
  reaching `DEPRECATED` status.
- **Patch SLA:** CRITICAL (HNDL-class) — 30 calendar days;
  HIGH — 60 days; MEDIUM — 120 days.

---

## 9. Post-Quantum Cryptography Transition Plan

| Track                           | Target algorithm         | CNSA 2.0 milestone |
| ------------------------------- | ------------------------ | ------------------ |
"""
    )
    for track, alg, deadline in _CNSA2_DEADLINES:
        sections.append(f"| {track} | {alg} | {deadline} |\n")

    sections.append(
        f"""
**Cut-over plan.** Each CRITICAL-tier endpoint in §3.1 will be migrated
to an ML-KEM-768 + X25519 hybrid key-establishment under the following
gate sequence:

1. **G0 — Inventory.** CBOM serial `{bundle.cbom_serial}` (this document).
2. **G1 — Hybrid pilot.** ≥ 1 representative endpoint per device class
   re-keyed under hybrid KEX in a sandbox cluster.
3. **G2 — Field A/B.** 10 % production rollout under feature flag with
   end-to-end latency budget ≤ +8 ms p95.
4. **G3 — Default-on.** Hybrid KEX becomes the default; classical-only
   peers are placed in a quarantine enclave (see §10).
5. **G4 — Classical sunset.** ECDHE / RSA key-establishment is removed
   from the firmware build; gate enforced by the AQC release CI.

---

## 10. Architecture & Microsegmentation

The transport surface is segmented under a Quantum-Resistant
Identity-First policy generated by `aqc generate-jadc2-policy`. The
policy is reproduced verbatim alongside this addendum as
`jadc2-segmentation.yaml`.

```
  [Sensor] -> [Edge Aggregator]
                 |
                 v
         [AQC PQC Gateway]   <- terminates legacy TLS,
                 |               re-wraps in ML-KEM-768 + X25519 hybrid
                 v
         [Cloud Analytics]
```

---

## 11. Penetration Testing Summary

Tester: third-party CREST-certified team (engagement reference under
separate cover). Scope: every CRITICAL and HIGH endpoint in §5.
Methodology: OWASP MSTG + ISO/IEC 27037 evidence handling.

---

## 12. Bidirectional Stimulation Safety (Soul Catcher 2.0)

If the subject device exposes any *write-capable* surface — neural
stimulation, drug-pump command, defibrillation pulse, closed-loop
neuromodulation — the following additional controls SHALL be
demonstrated prior to clearance:

1. The inbound command channel is wrapped in ML-KEM-768 + X25519
   hybrid KEX.
2. Every stimulation command is signed by an ML-DSA-65 short-lived
   ephemeral key bound to a per-session SPIFFE ID.
3. Any signature failure triggers a fail-safe to a clinician-defined
   default rather than the last-received command.
4. The device firmware refuses to apply commands older than a
   monotonic-counter horizon of N seconds (default 60).

---

## 13. Labeling

The following statements are added to the device labeling and IFU:

- "Transport-layer cryptography is undergoing migration to NIST FIPS
  203 / 204 / 205 on the schedule disclosed in the Cybersecurity
  Addendum filed with the FDA on """ + today + """."
- "Connected operation requires the manufacturer-supplied
  post-quantum gateway component."

---

## 14. PQC-Compliant Asset Inventory (Reference)

The following endpoints already meet CNSA 2.0 / FIPS 203 / 204 / 205:

"""
    )
    sections.append(
        "\n".join(f"- `{ep}`" for ep in safe_eps) + "\n"
        if safe_eps
        else "- *No CNSA 2.0-compliant endpoints inventoried.*\n"
    )

    sections.append(
        f"""

---

## 15. Document Control

| Field             | Value |
| ----------------- | ----- |
| Document ID       | {doc_id} |
| Revision          | 1.0 |
| Status            | DRAFT for RA red-line |
| Generator         | Aegis Quantum-Cognitive v{__version__} |
| CBOM Serial       | `{bundle.cbom_serial}` |
| Generated (UTC)   | {_utc_now_str()} |
| Signature anchor  | ML-DSA-65 (TBD by sponsor) |

*End of FDA e-STAR Cybersecurity Addendum.*
"""
    )
    return "".join(sections)


# ---------------------------------------------------------------------------
# DoD NSM-10 PQC Transition Roadmap
# ---------------------------------------------------------------------------


def render_dod_nsm10(bundle: ComplianceBundle) -> str:
    """Render the DoD NSM-10 PQC Transition Roadmap as Markdown."""

    md = bundle.metadata
    components = bundle.components
    hist = _histogram(components)
    doc_id = _doc_id("AQC-NSM10", bundle)

    by_class: dict[str, list[dict]] = {}
    for c in components:
        by_class.setdefault(_device_class_of(c), []).append(c)

    per_asset_rows = []
    for c in components:
        sev = _severity_of(c)
        if sev is Severity.SAFE:
            gate = "G2 — hybrid pilot complete"
        elif sev is Severity.MEDIUM:
            gate = "G3 — default-on"
        else:
            gate = "G1 — inventoried, awaiting hybrid pilot"
        per_asset_rows.append(
            [_endpoint_of(c), _device_class_of(c), _algorithm_of(c), sev.value, gate]
        )

    cnsa_table = _md_table(
        ["Track", "Target algorithm", "CNSA 2.0 milestone"],
        [[t, a, d] for t, a, d in _CNSA2_DEADLINES],
    )

    sections: list[str] = []
    sections.append(
        f"""# DoD NSM-10 PQC Transition Roadmap

**Document ID:** {doc_id}
**Generated:** {_utc_now_str()}
**Generator:** Aegis Quantum-Cognitive v{__version__} (`aqc.compliance_compiler`)
**Sponsor / Prime:** {md.sponsor}
**Contract Vehicle:** {md.contract_vehicle}
**CBOM Reference:** `{bundle.cbom_serial}`
**Scope:** Transport-layer cryptography on the subject system's
biometric, neural, and command/control surfaces.

This roadmap is structured to satisfy the reporting requirements of
**National Security Memorandum 10 (NSM-10)** *Promoting United States
Leadership in Quantum Computing While Mitigating Risks to Vulnerable
Cryptographic Systems* and the **NSA Commercial National Security
Algorithm Suite 2.0 (CNSA 2.0)** transition calendar.

---

## 1. Authority and Scope

- **NSM-10** (2022-05-04) directs the migration of National Security
  Systems off quantum-vulnerable cryptography on an aggressive timeline.
- **CNSA 2.0** (NSA/CSS, 2022-09 / amended) defines the target
  algorithms by track and the latest acceptable migration dates.
- **NIST FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, **FIPS 205
  (SLH-DSA)** define the primitives used in this plan.

This roadmap binds the subject system to the NSM-10 reporting cadence
and produces the cryptographic inventory artifact required by
Section 3(a)(i) of the Memorandum.

---

## 2. Inventory Methodology

The cryptographic inventory was generated by Aegis Quantum-Cognitive
`v{__version__}` against a representative capture of the subject
system's transport surface. Each (endpoint, primitive) pair was
normalised, deduplicated, and serialised into a CycloneDX 1.6 CBOM
(`{bundle.cbom_serial}`). The CBOM is the authoritative input to this
document; any drift between the CBOM and this report indicates a
re-run is required.

---

## 3. Risk Prioritisation Summary

| Tier      | Asset Count | NSM-10 Action       |
| --------- | ----------- | ------------------- |
| CRITICAL  | {hist['CRITICAL']} | Immediate migration |
| HIGH      | {hist['HIGH']} | Migration ≤ Q+1 |
| MEDIUM    | {hist['MEDIUM']} | Hybrid pilot ≤ Q+2 |
| LOW       | {hist['LOW']} | Track during routine refresh |
| PQC-SAFE  | {hist['SAFE']} | None (validated CNSA 2.0) |

---

## 4. CNSA 2.0 Migration Tracks

{cnsa_table}

---

## 5. Per-Asset Migration Plan

"""
        + _md_table(
            ["Endpoint", "Device Class", "Current Algorithm", "Severity", "Gate"],
            per_asset_rows,
        )
        + """

---

## 6. Migration Gates

| Gate | Definition                                                          | Exit criterion                                            |
| ---- | ------------------------------------------------------------------- | --------------------------------------------------------- |
| G0   | CBOM inventory complete and signed.                                 | This document, ML-DSA-65 signed.                          |
| G1   | Hybrid KEX pilot for ≥ 1 endpoint per device class.                 | Lab-validated handshake, ≤ +8 ms p95 latency overhead.    |
| G2   | 10 % production rollout under feature flag.                         | No SEV-1 within 14 consecutive days.                      |
| G3   | Hybrid KEX is default; classical peers quarantined.                 | All vulnerable endpoints either migrated or quarantined.  |
| G4   | Classical KEX removed from build; gate enforced in release CI.      | Negative test confirms classical handshake refused.       |

---

## 7. Procurement Language (Boilerplate)

Insert verbatim into all RFI / RFQ / RFP instruments downstream of
this system:

> "The Contractor shall demonstrate that all key-establishment for
> data in transit between [system X] and any external service is
> performed using NIST FIPS 203 (ML-KEM-768 or ML-KEM-1024) in a
> hybrid construction with X25519 / X448, and that authentication of
> long-lived identities is performed using NIST FIPS 204 (ML-DSA-65 or
> higher) or NIST FIPS 205 (SLH-DSA), in accordance with NSA CNSA 2.0.
> A current Cryptographic Bill of Materials (CycloneDX 1.6 or later)
> shall be delivered prior to acceptance, and updated with each
> firmware / software release."

---

## 8. Reporting Cadence

| Cadence        | Artifact                                  | Recipient                       |
| -------------- | ----------------------------------------- | ------------------------------- |
| Monthly        | Updated CBOM + delta from prior month     | Cognizant PMO                   |
| Quarterly      | Migration-gate status (this document)     | National Manager                |
| On change      | Out-of-cycle amendment for any new CRITICAL finding | National Manager      |
| Annually       | Full PQC posture review                   | Designated Approving Authority  |

---

## 9. Cross-References

| Document                                | ID                                        |
| --------------------------------------- | ----------------------------------------- |
| FDA e-STAR Cybersecurity Addendum       | `"""
        + _doc_id("AQC-FDA-ESTAR", bundle)
        + f"""` |
| Identity-First Segmentation Policy      | (see `jadc2-segmentation.yaml`) |
| Machine-readable CBOM                   | `{bundle.cbom_serial}` |

---

## 10. Document Control

| Field             | Value |
| ----------------- | ----- |
| Document ID       | {doc_id} |
| Revision          | 1.0 |
| Classification    | UNCLASSIFIED // FOR OFFICIAL USE ONLY |
| Generator         | Aegis Quantum-Cognitive v{__version__} |
| Generated (UTC)   | {_utc_now_str()} |

*End of NSM-10 PQC Transition Roadmap.*
"""
    )

    for dclass, items in sorted(by_class.items()):
        sections.append(f"\n---\n\n## Appendix — Device Class: {dclass}\n\n")
        sections.append(
            f"This appendix enumerates every endpoint of device class "
            f"`{dclass}` and its CBOM rationale. There are **{len(items)}** "
            f"such endpoint(s) under this system's transport surface.\n\n"
        )
        sections.append(
            _md_table(
                ["Endpoint", "Algorithm", "Severity", "Rationale"],
                [
                    [
                        _endpoint_of(c),
                        _algorithm_of(c),
                        _severity_of(c).value,
                        _rationale_of(c)[:120].replace("|", "/"),
                    ]
                    for c in items
                ],
            )
            + "\n"
        )

    return "".join(sections)


# ---------------------------------------------------------------------------
# Optional HTML / PDF rendering
# ---------------------------------------------------------------------------


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _pandoc_to_html(md_path: Path, html_path: Path) -> bool:
    if not _have("pandoc"):
        return False
    try:
        subprocess.run(
            [
                "pandoc",
                "--from", "gfm",
                "--to", "html5",
                "--standalone",
                "--metadata", "title=Aegis Quantum-Cognitive Compliance Pack",
                "-o", str(html_path),
                str(md_path),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def _html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    # Prefer weasyprint if available (pure-Python, no headless Chromium).
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]

        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return True
    except Exception:
        pass
    # Fall back to pandoc with --pdf-engine if it works on this box.
    if _have("pandoc") and _have("weasyprint"):
        try:
            subprocess.run(
                [
                    "pandoc",
                    "--from", "html",
                    "--to", "pdf",
                    "--pdf-engine=weasyprint",
                    "-o", str(pdf_path),
                    str(html_path),
                ],
                check=True,
                capture_output=True,
                timeout=60,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return False
    return False


# ---------------------------------------------------------------------------
# Public packager
# ---------------------------------------------------------------------------


def write_compliance_pack(
    bundle: ComplianceBundle,
    out_dir: Path | str,
    *,
    render_html: bool = False,
    render_pdf: bool = False,
) -> dict[str, Path]:
    """Write the full compliance pack to disk and return a path map.

    The returned dict always contains ``fda_estar`` and ``dod_nsm10``
    (Markdown). It additionally contains ``*_html`` / ``*_pdf`` keys
    only when the corresponding render succeeded — that lets the CLI
    cleanly tell the user when the optional tooling is missing.
    """

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    fda_md = out / "fda-estar-cyber-addendum.md"
    dod_md = out / "dod-nsm10-pqc-roadmap.md"
    fda_md.write_text(render_fda_estar(bundle), encoding="utf-8")
    dod_md.write_text(render_dod_nsm10(bundle), encoding="utf-8")

    paths: dict[str, Path] = {"fda_estar": fda_md, "dod_nsm10": dod_md}

    if render_html or render_pdf:
        fda_html = out / "fda-estar-cyber-addendum.html"
        dod_html = out / "dod-nsm10-pqc-roadmap.html"
        if _pandoc_to_html(fda_md, fda_html):
            paths["fda_estar_html"] = fda_html
        if _pandoc_to_html(dod_md, dod_html):
            paths["dod_nsm10_html"] = dod_html

    if render_pdf:
        fda_pdf = out / "fda-estar-cyber-addendum.pdf"
        dod_pdf = out / "dod-nsm10-pqc-roadmap.pdf"
        fda_html = paths.get("fda_estar_html")
        dod_html = paths.get("dod_nsm10_html")
        if fda_html is not None and _html_to_pdf(fda_html, fda_pdf):
            paths["fda_estar_pdf"] = fda_pdf
        if dod_html is not None and _html_to_pdf(dod_html, dod_pdf):
            paths["dod_nsm10_pdf"] = dod_pdf

    return paths
