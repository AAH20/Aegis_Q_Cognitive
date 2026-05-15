"""Cryptographic Bill of Materials (CBOM) generator.

Walks a PCAP (or a synthetic stream when scapy / a real capture is not
available) and emits a CycloneDX-style CBOM that maps every neural,
biometric, and JADC2 endpoint to the cryptographic primitive currently
protecting it. Classical primitives (RSA / ECC / ECDH) are flagged as
``CRITICAL Q-DAY VULNERABILITY`` so the artifact maps directly onto the
NSM-10 inventory mandate.

The module is intentionally tolerant of missing dependencies: if
``scapy`` is unavailable the analyzer falls back to a deterministic
synthetic stream so the CLI can still demo on an air-gapped laptop.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Iterator, Optional

from . import CLASSICAL_VULNERABLE, PQC_APPROVED, __version__
from ._models import CryptoAsset, DeviceClass, Severity
from .akb import AKB, append_compliance_tail

try:  # scapy is heavy; allow the module to load without it.
    from scapy.all import PcapReader  # type: ignore[import-untyped]

    _HAS_SCAPY = True
except Exception:  # pragma: no cover - exercised only when scapy missing
    PcapReader = None  # type: ignore[assignment]
    _HAS_SCAPY = False


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# TLS cipher-suite fragments → (algorithm family, key-exchange family)
# Order matters: PQC hints are checked first so a hybrid suite like
# ``TLS_MLKEM768_X25519_AES_256_GCM`` is classified as ML-KEM, not X25519.
_TLS_CIPHER_HINTS: tuple[tuple[str, str], ...] = (
    ("KYBER", "ML-KEM"),
    ("ML_KEM", "ML-KEM"),
    ("ML-KEM", "ML-KEM"),
    ("MLKEM", "ML-KEM"),
    ("DILITHIUM", "ML-DSA"),
    ("ML_DSA", "ML-DSA"),
    ("ML-DSA", "ML-DSA"),
    ("SPHINCS", "SLH-DSA"),
    ("SLH-DSA", "SLH-DSA"),
    ("FALCON", "FALCON"),
    ("ECDHE_ECDSA", "ECDHE"),
    ("ECDHE_RSA", "ECDHE"),
    ("ECDHE", "ECDHE"),
    ("ECDH", "ECDH"),
    ("X25519", "X25519"),
    ("X448", "X448"),
    ("DHE_RSA", "DHE"),
    ("DHE", "DHE"),
    ("RSA_WITH", "RSA"),
    ("RSA", "RSA"),
)

# Bluetooth / BLE / proprietary BCI fingerprints by manufacturer hint.
_BCI_VENDOR_HINTS: dict[str, DeviceClass] = {
    "neuralink": DeviceClass.BCI,
    "synchron": DeviceClass.BCI,
    "blackrock": DeviceClass.BCI,
    "kernel": DeviceClass.BCI,
    "emotiv": DeviceClass.EEG_WEARABLE,
    "muse": DeviceClass.EEG_WEARABLE,
    "neurosky": DeviceClass.EEG_WEARABLE,
    "oura": DeviceClass.BIOMETRIC_RING,
    "whoop": DeviceClass.BIOMETRIC_RING,
    "apple-watch": DeviceClass.SMART_WATCH,
    "garmin": DeviceClass.SMART_WATCH,
    "medtronic": DeviceClass.MEDTECH_IMPLANT,
    "boston-sci": DeviceClass.MEDTECH_IMPLANT,
    "link16": DeviceClass.JADC2_RADIO,
    "tac-radio": DeviceClass.JADC2_RADIO,
}


def _normalize_algorithm(raw: str) -> str:
    """Collapse a noisy cipher string to a canonical algorithm token."""

    token = raw.upper().replace(" ", "").replace("/", "_")
    for needle, family in _TLS_CIPHER_HINTS:
        if needle in token:
            return family
    # Fall back to the first token before an underscore.
    return token.split("_", 1)[0] or "UNKNOWN"


def _device_class_for(hint: str) -> DeviceClass:
    """Best-effort mapping from a vendor/host hint to a DeviceClass."""

    needle = hint.lower()
    for vendor, dclass in _BCI_VENDOR_HINTS.items():
        if vendor in needle:
            return dclass
    if re.search(r"bci|n3|cortex|neural|brain", needle):
        return DeviceClass.BCI
    if re.search(r"eeg|headset", needle):
        return DeviceClass.EEG_WEARABLE
    if re.search(r"ring|patch|biom", needle):
        return DeviceClass.BIOMETRIC_RING
    if re.search(r"watch|wrist", needle):
        return DeviceClass.SMART_WATCH
    if re.search(r"implant|pacemaker|stim", needle):
        return DeviceClass.MEDTECH_IMPLANT
    if re.search(r"jadc2|link\-?16|tactical", needle):
        return DeviceClass.JADC2_RADIO
    return DeviceClass.UNKNOWN


def _severity_for(
    algorithm: str, device_class: DeviceClass, akb: AKB | None = None
) -> tuple[Severity, str]:
    """Score the (algorithm, device) pair against CNSA 2.0 expectations."""

    algo = algorithm.upper()
    high_value = device_class in {
        DeviceClass.BCI,
        DeviceClass.EEG_WEARABLE,
        DeviceClass.JADC2_RADIO,
        DeviceClass.MEDTECH_IMPLANT,
    }

    if algo in PQC_APPROVED:
        return Severity.SAFE, "NIST PQC primitive; CNSA 2.0 compliant."
    if algo in CLASSICAL_VULNERABLE:
        if high_value:
            msg = (
                "CRITICAL Q-DAY VULNERABILITY: classical asymmetric crypto "
                "protecting cognitively-sensitive telemetry. Adversary "
                "HNDL captures decrypt on Q-Day via Shor's algorithm."
            )
            return (
                Severity.CRITICAL,
                append_compliance_tail(msg, "cbom.classical_asymmetric_on_cognitive", akb),
            )
        msg = (
            "Classical asymmetric crypto. HNDL exposure pending "
            "CNSA 2.0 migration."
        )
        return (
            Severity.HIGH,
            append_compliance_tail(msg, "cbom.classical_asymmetric_on_cognitive", akb),
        )
    if algo in {"AES", "AES-128", "AES-256", "CHACHA20"}:
        return (
            Severity.LOW,
            "Symmetric-only channel; Grover at most halves margin. "
            "Verify key-establishment upstream.",
        )
    return Severity.MEDIUM, f"Unrecognised algorithm '{algorithm}'."


# ---------------------------------------------------------------------------
# Stream ingestion
# ---------------------------------------------------------------------------


def _iter_pcap_assertions(
    pcap_path: Path,
) -> Iterator[tuple[str, int, str, str]]:
    """Yield (host, port, raw_algo, vendor_hint) tuples from a PCAP.

    Only TLS ClientHello-ish payloads are parsed; everything else is
    skipped silently. This deliberately uses heuristics instead of a
    real TLS parser so the file works on truncated captures.
    """

    if not _HAS_SCAPY or PcapReader is None:
        return
    cipher_pattern = re.compile(
        r"(TLS_[A-Z0-9_]+|ECDHE[_A-Z0-9]*|RSA[_A-Z0-9]*|KYBER\w*|"
        r"ML[_-]?KEM\w*|DILITHIUM\w*|FALCON\w*|SPHINCS\w*)",
        re.IGNORECASE,
    )
    sni_pattern = re.compile(rb"[\x00-\x20]([a-z0-9\-\.]{4,64})\.(com|io|mil|gov)")
    try:
        with PcapReader(str(pcap_path)) as reader:  # type: ignore[misc]
            for pkt in reader:
                payload = bytes(pkt.payload) if hasattr(pkt, "payload") else b""
                try:
                    text = payload.decode("latin-1", errors="ignore")
                except Exception:
                    continue
                cipher_match = cipher_pattern.search(text)
                if not cipher_match:
                    continue
                host = "unknown"
                if (m := sni_pattern.search(payload)) is not None:
                    host = m.group(1).decode("latin-1", errors="ignore")
                port = getattr(getattr(pkt, "payload", None), "dport", 443) or 443
                yield host, int(port), cipher_match.group(0), host
    except Exception:
        return


def _synthetic_assertions(
    seed: Optional[int] = None,
) -> Iterator[tuple[str, int, str, str]]:
    """Deterministic synthetic neural-fleet stream for offline demos."""

    rng = random.Random(seed if seed is not None else 1337)
    fleet: tuple[tuple[str, int, DeviceClass, tuple[str, ...]], ...] = (
        ("neuralink-n1-prime.bci.local",        9443, DeviceClass.BCI,
            ("TLS_ECDHE_RSA_WITH_AES_256_GCM", "RSA-2048")),
        ("synchron-stentrode.bci.local",        9443, DeviceClass.BCI,
            ("TLS_RSA_WITH_AES_256_CBC",)),
        ("blackrock-neuroport.darpa-n3.local",  8883, DeviceClass.BCI,
            ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM",)),
        ("kernel-flow2.eeg.local",              443,  DeviceClass.EEG_WEARABLE,
            ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",)),
        ("emotiv-epocx.eeg.local",              443,  DeviceClass.EEG_WEARABLE,
            ("TLS_RSA_WITH_AES_128_CBC",)),
        ("oura-gen4.biometric.local",           443,  DeviceClass.BIOMETRIC_RING,
            ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM",)),
        ("whoop-5.biometric.local",             443,  DeviceClass.BIOMETRIC_RING,
            ("TLS_ECDHE_RSA_WITH_AES_256_GCM",)),
        ("apple-watch-u2.smart.local",          443,  DeviceClass.SMART_WATCH,
            ("TLS_AES_256_GCM_SHA384+X25519",)),
        ("medtronic-azure.implant.local",       8443, DeviceClass.MEDTECH_IMPLANT,
            ("TLS_RSA_WITH_AES_256_CBC",)),
        ("link16-radio-7.jadc2.mil",            6443, DeviceClass.JADC2_RADIO,
            ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM",)),
        ("tac-radio-pq-12.jadc2.mil",           6443, DeviceClass.JADC2_RADIO,
            ("TLS_MLKEM768_X25519_AES_256_GCM",)),
        ("aegis-pqc-gateway.jadc2.mil",         6443, DeviceClass.JADC2_RADIO,
            ("TLS_MLKEM768_ML_DSA65_AES_256_GCM",)),
    )
    for host, port, _dclass, ciphers in fleet:
        cipher = rng.choice(ciphers)
        yield host, port, cipher, host


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_assets(
    pcap: Optional[Path | str] = None,
    *,
    seed: Optional[int] = None,
    knowledge_root: Optional[Path] = None,
) -> list[CryptoAsset]:
    """Produce a deduplicated list of :class:`CryptoAsset` from a stream.

    Parameters
    ----------
    pcap:
        Optional path to a PCAP / PCAPNG file. When ``None`` (or scapy is
        unavailable) a deterministic synthetic neural fleet is used.
    seed:
        Optional seed for the synthetic generator. Useful for tests.
    knowledge_root:
        Optional path to a ``knowledge_base/`` tree (defaults / env / packaged).
    """

    try:
        akb = AKB.load(knowledge_root)
    except (FileNotFoundError, ImportError):
        akb = None

    raw: Iterable[tuple[str, int, str, str]]
    if pcap is None:
        raw = _synthetic_assertions(seed=seed)
    else:
        path = Path(pcap)
        pcap_assertions = list(_iter_pcap_assertions(path))
        raw = pcap_assertions or _synthetic_assertions(seed=seed)

    seen: dict[tuple[str, int, str], CryptoAsset] = {}
    for host, port, raw_algo, hint in raw:
        algorithm = _normalize_algorithm(raw_algo)
        device_class = _device_class_for(hint)
        severity, rationale = _severity_for(algorithm, device_class, akb)
        key = (host, port, algorithm)
        if key in seen:
            continue
        seen[key] = CryptoAsset(
            host=host,
            port=port,
            algorithm=algorithm,
            protocol="TLS" if "TLS" in raw_algo.upper() else "RAW",
            device_class=device_class,
            severity=severity,
            rationale=rationale,
        )
    return sorted(
        seen.values(),
        key=lambda a: (a.severity.value, a.host, a.port),
    )


def generate_cbom(
    assets: list[CryptoAsset],
    *,
    target: str = "aqc-fleet",
) -> dict:
    """Serialise a list of crypto assets to a CycloneDX 1.6-style CBOM dict.

    The result is intentionally structured to be valid input to the
    CycloneDX `crypto-assets` extension once a real signer is wired in.
    """

    digest = hashlib.sha256()
    components: list[dict] = []
    for asset in assets:
        digest.update(f"{asset.endpoint}|{asset.algorithm}".encode("utf-8"))
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": (
                    f"crypto:{asset.algorithm.lower()}@{asset.endpoint}"
                ),
                "name": asset.algorithm,
                "evidence": {
                    "endpoint": asset.endpoint,
                    "protocol": asset.protocol,
                    "device_class": asset.device_class.value,
                },
                "properties": [
                    {"name": "aqc:severity", "value": asset.severity.value},
                    {"name": "aqc:rationale", "value": asset.rationale},
                    {
                        "name": "aqc:quantum_safe",
                        "value": "true"
                        if asset.severity is Severity.SAFE
                        else "false",
                    },
                ],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:aqc:{digest.hexdigest()[:32]}",
        "metadata": {
            "tool": {
                "vendor": "Aegis Quantum-Cognitive",
                "name": "aqc-cbom",
                "version": __version__,
            },
            "component": {"type": "system", "name": target},
        },
        "components": components,
    }


def summarise(assets: list[CryptoAsset]) -> dict[str, int]:
    """Return a {severity: count} histogram for a CBOM."""

    out: dict[str, int] = {s.value: 0 for s in Severity}
    for asset in assets:
        out[asset.severity.value] += 1
    return out


def assets_to_records(assets: list[CryptoAsset]) -> list[dict]:
    """Return JSON-serialisable dicts (helpful for ``rich`` tables / tests)."""

    records: list[dict] = []
    for asset in assets:
        rec = asdict(asset)
        rec["device_class"] = asset.device_class.value
        rec["severity"] = asset.severity.value
        records.append(rec)
    return records


def dump_cbom(cbom: dict, path: Path | str) -> Path:
    """Write a CBOM dict to disk as pretty JSON and return the path."""

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cbom, indent=2), encoding="utf-8")
    return out
