"""HNDL (Harvest Now, Decrypt Later) analyzer — the Soul Catcher Auditor.

This module looks at "data in transit" and decides whether a given
endpoint is exposed to retroactive quantum decryption. The classifier
is heuristic on purpose: the goal is to surface streams whose
*biophysical fingerprint* matches DARPA N3 / Soul Catcher 1.0 telemetry
(high packet rate, low jitter, payload entropy approaching the
Shannon ceiling) and which are currently riding on classical asymmetric
cryptography.

Two top-level verdicts are produced:

* ``HNDL Exposure``   — the stream is worth harvesting because it
  contains high-entropy, low-latency neural telemetry encrypted with
  RSA / ECC / ECDH.
* ``Soul Catcher 2.0 Vector`` — the same stream additionally exposes a
  *cognitive baseline* that, once decrypted on Q-Day, can be replayed
  back at the target to spoof neural input (active injection).
"""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import CLASSICAL_VULNERABLE, PQC_APPROVED
from ._models import CryptoAsset, DeviceClass, HNDLFinding, Severity
from .akb import AKB, append_compliance_tail

# ---------------------------------------------------------------------------
# HNDLAnalyzer defaults come from ``knowledge_base/`` (see ``akb.AKB``).
# Legacy names below mirror the packaged ontology for tests / introspection.
# ---------------------------------------------------------------------------

_BOOT_AKB: AKB | None
try:  # pragma: no branch - import-time load for stable module constants
    _BOOT_AKB = AKB.load()
except (FileNotFoundError, ImportError, KeyError, TypeError, ValueError):
    _BOOT_AKB = None

ENTROPY_CIPHERTEXT_FLOOR: float = (
    _BOOT_AKB.neural.entropy_floor_bits_per_byte if _BOOT_AKB else 7.2
)
NEURAL_RATE_FLOOR_HZ: float = (
    _BOOT_AKB.neural.rate_floor_hz if _BOOT_AKB else 200.0
)
NEURAL_LATENCY_CEILING_MS: float = (
    _BOOT_AKB.neural.latency_ceiling_ms if _BOOT_AKB else 25.0
)
Q_DAY_TARGET_YEAR: int = _BOOT_AKB.slater.q_day_year if _BOOT_AKB else 2030


@dataclass(slots=True)
class StreamSample:
    """One sampled flow used as input to the HNDL classifier."""

    endpoint: str
    device_class: DeviceClass
    algorithm: str
    payload: bytes
    inter_arrival_ms: Sequence[float]

    @property
    def packet_rate_hz(self) -> float:
        if not self.inter_arrival_ms:
            return 0.0
        mean_ms = statistics.fmean(self.inter_arrival_ms)
        return 0.0 if mean_ms <= 0 else 1000.0 / mean_ms

    @property
    def median_latency_ms(self) -> float:
        if not self.inter_arrival_ms:
            return float("inf")
        return statistics.median(self.inter_arrival_ms)


# ---------------------------------------------------------------------------
# Public analyzer
# ---------------------------------------------------------------------------


class HNDLAnalyzer:
    """Audit "data in transit" for HNDL and Soul Catcher 2.0 exposure."""

    def __init__(
        self,
        *,
        entropy_floor: float | None = None,
        rate_floor_hz: float | None = None,
        latency_ceiling_ms: float | None = None,
        q_day_year: int | None = None,
        akb: AKB | None = None,
        knowledge_root: Path | None = None,
    ) -> None:
        self._akb = akb if akb is not None else AKB.load(knowledge_root)
        self.entropy_floor = (
            entropy_floor
            if entropy_floor is not None
            else self._akb.neural.entropy_floor_bits_per_byte
        )
        self.rate_floor_hz = (
            rate_floor_hz
            if rate_floor_hz is not None
            else self._akb.neural.rate_floor_hz
        )
        self.latency_ceiling_ms = (
            latency_ceiling_ms
            if latency_ceiling_ms is not None
            else self._akb.neural.latency_ceiling_ms
        )
        self.q_day_year = (
            q_day_year if q_day_year is not None else self._akb.slater.q_day_year
        )
        self.threat_profile_id = self._akb.slater.profile_id

    # -- Core scoring --------------------------------------------------------

    @staticmethod
    def shannon_entropy(payload: bytes) -> float:
        """Return Shannon entropy in bits per byte (0.0 - 8.0)."""

        if not payload:
            return 0.0
        counts = Counter(payload)
        length = len(payload)
        return -sum(
            (c / length) * math.log2(c / length) for c in counts.values()
        )

    def _is_classical(self, algorithm: str) -> bool:
        algo = algorithm.upper()
        if algo in PQC_APPROVED:
            return False
        # Anything containing PQC token wins — covers hybrid suites.
        if any(tok in algo for tok in ("MLKEM", "ML-KEM", "DILITHIUM", "FALCON", "SPHINCS")):
            return False
        return algo in CLASSICAL_VULNERABLE or any(
            tok in algo
            for tok in ("RSA", "ECDH", "ECDHE", "ECDSA", "DHE", "X25519", "X448")
        )

    @staticmethod
    def _is_high_value(device_class: DeviceClass) -> bool:
        return device_class in {
            DeviceClass.BCI,
            DeviceClass.EEG_WEARABLE,
            DeviceClass.MEDTECH_IMPLANT,
            DeviceClass.JADC2_RADIO,
        }

    def classify(self, sample: StreamSample) -> HNDLFinding:
        """Classify a single stream sample and return an :class:`HNDLFinding`."""

        entropy = self.shannon_entropy(sample.payload)
        rate = sample.packet_rate_hz
        latency = sample.median_latency_ms

        looks_neural = (
            entropy >= self.entropy_floor
            and rate >= self.rate_floor_hz
            and latency <= self.latency_ceiling_ms
        )
        classical = self._is_classical(sample.algorithm)
        cognitive_target = self._is_high_value(sample.device_class)

        # Severity grid: (looks_neural × classical × cognitive_target).
        if looks_neural and classical and cognitive_target:
            severity = Severity.CRITICAL
            soul_catcher_vector = True
            cardiac_surface = (
                latency <= self._akb.cardiac.latency_threshold_ms and classical
            )
            cardiac_frag = ""
            if cardiac_surface:
                cardiac_frag = (
                    f" AKB bio-cyber ontology: sub-{self._akb.cardiac.latency_threshold_ms} ms "
                    f"median inter-arrival intersects cardiac-timing surface "
                    f"({self._akb.cardiac.vulnerable_phase})."
                )
            notes = (
                f"HNDL EXPLOITATION HIGHLY LIKELY ({self.threat_profile_id}). Stream matches "
                f"DARPA-N3 / Soul Catcher 1.0 fingerprint (entropy "
                f"{entropy:.2f} bpb, {rate:.0f} Hz, {latency:.1f} ms) "
                f"and is wrapped in classical {sample.algorithm}. "
                f"Soul Catcher 2.0 vector: harvested today, brain-print "
                f"decrypted by ~{self.q_day_year} via Shor and replayed "
                f"as cognitive injection into JADC2 BCI loops.{cardiac_frag}"
            )
            notes = append_compliance_tail(
                notes, "hndl.soul_catcher_2_0_vector", self._akb
            )
        elif looks_neural and classical:
            severity = Severity.HIGH
            soul_catcher_vector = False
            notes = (
                "HNDL exposure: classical-encrypted high-entropy "
                "telemetry. Cognitive-value low but biometric "
                "re-identification still possible post Q-Day."
            )
        elif classical and cognitive_target:
            severity = Severity.MEDIUM
            soul_catcher_vector = False
            notes = (
                "Classical crypto on a cognitive-class endpoint. Stream "
                "fingerprint does not currently match neural telemetry; "
                "rescan during active session."
            )
        elif classical:
            severity = Severity.LOW
            soul_catcher_vector = False
            notes = "Classical crypto on non-cognitive endpoint."
        else:
            severity = Severity.SAFE
            soul_catcher_vector = False
            notes = (
                f"PQC-wrapped channel ({sample.algorithm}); CNSA 2.0 "
                "compliant. No HNDL exposure detected."
            )

        return HNDLFinding(
            endpoint=sample.endpoint,
            device_class=sample.device_class,
            algorithm=sample.algorithm,
            entropy_bits_per_byte=round(entropy, 3),
            packet_rate_hz=round(rate, 2),
            median_latency_ms=round(latency, 2),
            severity=severity,
            soul_catcher_vector=soul_catcher_vector,
            notes=notes,
        )

    def analyze(self, samples: Iterable[StreamSample]) -> list[HNDLFinding]:
        """Classify many samples; results are sorted worst-first."""

        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.SAFE: 4,
        }
        findings = [self.classify(s) for s in samples]
        findings.sort(key=lambda f: (order[f.severity], f.endpoint))
        return findings


# ---------------------------------------------------------------------------
# Sample generators (used by the CLI when no real PCAP is available)
# ---------------------------------------------------------------------------


def _ciphertext_blob(rng: random.Random, n: int = 1024) -> bytes:
    """Random bytes — entropy ≈ 8.0 bpb, indistinguishable from ciphertext."""

    return bytes(rng.getrandbits(8) for _ in range(n))


def _low_entropy_blob(rng: random.Random, n: int = 1024) -> bytes:
    """Repetitive payload — entropy ≈ 1-3 bpb."""

    motif = bytes(rng.getrandbits(8) for _ in range(8))
    return (motif * ((n // len(motif)) + 1))[:n]


def _neural_intervals(
    rng: random.Random, rate_hz: float, jitter_ms: float, count: int = 64
) -> list[float]:
    base = 1000.0 / max(rate_hz, 1.0)
    return [max(0.05, rng.gauss(base, jitter_ms)) for _ in range(count)]


def synthetic_samples(
    assets: Sequence[CryptoAsset] | None = None,
    *,
    seed: int | None = None,
) -> list[StreamSample]:
    """Synthesise stream samples that match a list of assets (or a default fleet)."""

    rng = random.Random(seed if seed is not None else 4242)
    if assets is None:
        # Mirror the synthetic fleet from cbom_generator for symmetry.
        from .cbom_generator import scan_assets

        assets = scan_assets(seed=seed)

    samples: list[StreamSample] = []
    for asset in assets:
        if asset.device_class in {
            DeviceClass.BCI,
            DeviceClass.EEG_WEARABLE,
        }:
            payload = _ciphertext_blob(rng)
            intervals = _neural_intervals(rng, rate_hz=512.0, jitter_ms=1.5)
        elif asset.device_class is DeviceClass.MEDTECH_IMPLANT:
            payload = _ciphertext_blob(rng)
            intervals = _neural_intervals(rng, rate_hz=256.0, jitter_ms=4.0)
        elif asset.device_class is DeviceClass.BIOMETRIC_RING:
            payload = _ciphertext_blob(rng, n=256)
            intervals = _neural_intervals(rng, rate_hz=4.0, jitter_ms=80.0)
        elif asset.device_class is DeviceClass.SMART_WATCH:
            payload = _ciphertext_blob(rng, n=256)
            intervals = _neural_intervals(rng, rate_hz=8.0, jitter_ms=40.0)
        elif asset.device_class is DeviceClass.JADC2_RADIO:
            payload = _ciphertext_blob(rng)
            intervals = _neural_intervals(rng, rate_hz=300.0, jitter_ms=2.0)
        else:
            payload = _low_entropy_blob(rng)
            intervals = _neural_intervals(rng, rate_hz=2.0, jitter_ms=200.0)
        samples.append(
            StreamSample(
                endpoint=asset.endpoint,
                device_class=asset.device_class,
                algorithm=asset.algorithm,
                payload=payload,
                inter_arrival_ms=intervals,
            )
        )
    return samples


def stream_samples_from_pcap(
    pcap_path: Path | str,
) -> Iterator[StreamSample]:
    """Best-effort streaming reader from a real PCAP.

    Falls back to ``yield from ()`` when scapy is unavailable so callers
    can compose this with :func:`synthetic_samples`.
    """

    try:
        from scapy.all import PcapReader  # type: ignore[import-untyped]
    except Exception:
        return

    from .cbom_generator import _device_class_for, _normalize_algorithm  # noqa: WPS437

    path = Path(pcap_path)
    flows: dict[str, dict] = {}
    try:
        with PcapReader(str(path)) as reader:  # type: ignore[misc]
            for pkt in reader:
                try:
                    src = getattr(pkt, "src", "0.0.0.0")
                    dst = getattr(pkt, "dst", "0.0.0.0")
                    sport = getattr(getattr(pkt, "payload", None), "sport", 0)
                    dport = getattr(getattr(pkt, "payload", None), "dport", 0)
                    ts = float(getattr(pkt, "time", 0.0))
                    payload = bytes(pkt.payload.payload) if hasattr(pkt, "payload") else b""
                except Exception:
                    continue
                flow_key = f"{src}:{sport}->{dst}:{dport}"
                flow = flows.setdefault(
                    flow_key,
                    {"ts": [], "payload": bytearray(), "host": dst, "port": dport or 0},
                )
                flow["ts"].append(ts)
                flow["payload"].extend(payload[:64])

        for flow_key, flow in flows.items():
            ts = flow["ts"]
            if len(ts) < 4:
                continue
            intervals = [
                max(0.05, (b - a) * 1000.0) for a, b in zip(ts, ts[1:], strict=False)
            ]
            yield StreamSample(
                endpoint=f"{flow['host']}:{flow['port']}",
                device_class=_device_class_for(flow_key),
                algorithm=_normalize_algorithm("UNKNOWN"),
                payload=bytes(flow["payload"]),
                inter_arrival_ms=intervals,
            )
    except Exception:
        return
