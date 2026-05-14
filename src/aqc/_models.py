"""Shared dataclasses used across CBOM, HNDL, and JADC2 modules.

These types intentionally mirror the language of the DoD PQC migration
playbook (NSM-10 / CNSA 2.0) and NIST FIPS 203/204/205 so the artifacts
produced by AQC drop cleanly into a JADC2 risk register.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Risk severity tiers aligned to CNSA 2.0 transition deadlines."""

    CRITICAL = "CRITICAL"   # Vulnerable to HNDL today, sensitive past 2030.
    HIGH = "HIGH"           # Vulnerable to HNDL today, low cognitive value.
    MEDIUM = "MEDIUM"       # Hybrid / partial PQC, residual risk.
    LOW = "LOW"             # Symmetric-only or short-lived ephemeral data.
    SAFE = "SAFE"           # Pure NIST PQC suite, CNSA 2.0 compliant.


class DeviceClass(str, Enum):
    """Classes of telemetry endpoints that AQC inspects."""

    BCI = "BCI"                       # DARPA N3 / Soul Catcher-class BCI.
    EEG_WEARABLE = "EEG_WEARABLE"     # Consumer EEG / dry-electrode headset.
    BIOMETRIC_RING = "BIOMETRIC_RING" # HRV/SpO2/temperature ring or patch.
    SMART_WATCH = "SMART_WATCH"       # PPG + ECG capable wrist wearable.
    MEDTECH_IMPLANT = "MEDTECH_IMPLANT"
    JADC2_RADIO = "JADC2_RADIO"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class CryptoAsset:
    """A single (host, port, algorithm) crypto assertion drawn from traffic."""

    host: str
    port: int
    algorithm: str
    key_size: Optional[int] = None
    protocol: str = "TLS"
    device_class: DeviceClass = DeviceClass.UNKNOWN
    severity: Severity = Severity.MEDIUM
    rationale: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(slots=True)
class HNDLFinding:
    """One HNDL exposure verdict for a neural / biometric stream."""

    endpoint: str
    device_class: DeviceClass
    algorithm: str
    entropy_bits_per_byte: float
    packet_rate_hz: float
    median_latency_ms: float
    severity: Severity
    soul_catcher_vector: bool
    notes: str
    detected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(slots=True)
class SegmentationPolicy:
    """Proposed Layer-3 quantum-safe microsegmentation policy."""

    enclave_name: str
    isolated_endpoints: list[str]
    allowed_peers: list[str]
    pqc_kex: str
    pqc_sig: str
    deny_by_default: bool = True
    require_mtls_pqc: bool = True
    notes: str = ""
