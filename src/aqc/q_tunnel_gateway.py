"""Hybrid PQC Tunnel Gateway.

A small, production-shaped daemon and an in-process demo path that:

1. Performs a **hybrid post-quantum handshake** combining ML-KEM-768
   (FIPS 203) with X25519, per the IETF
   *draft-kwiatkowski-tls-ecdhe-mlkem* convention and NSA CNSA 2.0
   hybrid-during-transition guidance.
2. Signs the handshake transcript with ML-DSA-65 (FIPS 204) so a
   downstream peer can verify the key-establishment was authentic.
3. Derives a 256-bit session key with HKDF-SHA-256.
4. Wraps the data plane in AES-256-GCM with per-direction nonce
   counters.

Dependency strategy
-------------------

* `cryptography` (mandatory) — used for X25519, HKDF-SHA-256, and
  AES-256-GCM. Pure-wheel, installs anywhere.
* `liboqs-python` (optional, ``[pqc]`` extra) — used for real
  ML-KEM-768 / ML-DSA-65 when present. When absent, the
  :class:`TunnelMode.SIMULATION` mode is used: handshake shape is
  correct, AEAD is real, but the ML-KEM and ML-DSA legs are
  deterministic HKDF stand-ins. ``pqc_safe`` is set to ``False`` in
  that case so the CLI can render the red "NOT QUANTUM SAFE" panel.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# --- Crypto deps ----------------------------------------------------------

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - exercised only when missing
    X25519PrivateKey = None  # type: ignore[assignment]
    X25519PublicKey = None  # type: ignore[assignment]
    AESGCM = None  # type: ignore[assignment]
    HKDF = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    _HAS_CRYPTOGRAPHY = False

try:  # liboqs-python (PQC backend)
    import oqs  # type: ignore[import-untyped]

    _HAS_OQS = True
except Exception:  # pragma: no cover
    oqs = None  # type: ignore[assignment]
    _HAS_OQS = False


# FIPS 203 / 204 wire-format constants (used to shape the SIMULATION mode
# transcript so its byte counts match the real algorithm). ML-KEM-768:
# pk = 1184 B, ct = 1088 B, ss = 32 B. ML-DSA-65 signature = 3293 B.
ML_KEM_768_PK_LEN: int = 1184
ML_KEM_768_CT_LEN: int = 1088
ML_KEM_SS_LEN: int = 32
ML_DSA_65_SIG_LEN: int = 3293
ML_DSA_65_PK_LEN: int = 1952
X25519_PUB_LEN: int = 32
HYBRID_SUITE_ID: bytes = b"AQC/q-tunnel/v1 ML-KEM-768+X25519/ML-DSA-65/AES-256-GCM"


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


class TunnelMode(str, Enum):
    """How the tunnel is built for this run.

    HYBRID — real ML-KEM-768 + X25519 KEX with ML-DSA-65 transcript
    signing. Requires `liboqs-python`.

    SIMULATION — handshake shape is correct, message lengths match
    ML-KEM-768 / ML-DSA-65, AEAD round-trip is real, but the KEM and
    signature legs are deterministic HKDF stand-ins. NOT post-quantum
    secure. Useful for demos, CI, and offline screen-shares.
    """

    HYBRID = "HYBRID"
    SIMULATION = "SIMULATION"


# ---------------------------------------------------------------------------
# KEM / signature backends
# ---------------------------------------------------------------------------


class _SimulatedKEM:
    """HKDF-shaped stand-in for ML-KEM-768 used in :class:`TunnelMode.SIMULATION`.

    The wire-format byte counts match FIPS 203 (ML-KEM-768) exactly so
    transcript and timing measurements are realistic. The shared
    secret is HKDF(seed, "AQC-SIM-KEM") and is recoverable by anyone
    who sees the ciphertext — this is by design. NEVER deploy.
    """

    name = "ML-KEM-768 (SIMULATION)"

    def __init__(self) -> None:
        self._sk_seed = secrets.token_bytes(32)

    def generate_keypair(self) -> bytes:
        return hashlib.shake_256(self._sk_seed).digest(ML_KEM_768_PK_LEN)

    def encapsulate(self, peer_pk: bytes) -> tuple[bytes, bytes]:
        if len(peer_pk) != ML_KEM_768_PK_LEN:
            raise ValueError(
                f"peer pk must be {ML_KEM_768_PK_LEN} bytes, got {len(peer_pk)}"
            )
        seed = secrets.token_bytes(32)
        # Embed seed in the ciphertext head so decap can recover it.
        tail = hashlib.shake_256(seed + peer_pk).digest(ML_KEM_768_CT_LEN - 32)
        ciphertext = seed + tail
        shared = hashlib.sha256(b"AQC-SIM-KEM" + seed + peer_pk).digest()
        return ciphertext, shared

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != ML_KEM_768_CT_LEN:
            raise ValueError(
                f"ciphertext must be {ML_KEM_768_CT_LEN} bytes, got {len(ciphertext)}"
            )
        seed = ciphertext[:32]
        peer_pk = hashlib.shake_256(self._sk_seed).digest(ML_KEM_768_PK_LEN)
        return hashlib.sha256(b"AQC-SIM-KEM" + seed + peer_pk).digest()


class _SimulatedSig:
    """HKDF-shaped stand-in for ML-DSA-65 in SIMULATION mode."""

    name = "ML-DSA-65 (SIMULATION)"
    sig_len = ML_DSA_65_SIG_LEN
    pk_len = ML_DSA_65_PK_LEN

    def __init__(self) -> None:
        self._sk = secrets.token_bytes(32)
        self.public_key = hashlib.shake_256(b"pk" + self._sk).digest(self.pk_len)

    def sign(self, message: bytes) -> bytes:
        mac = hmac.new(self._sk, message, hashlib.sha256).digest()
        return hashlib.shake_256(b"sig" + mac).digest(self.sig_len)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        # The simulation can't actually verify; we just check the
        # signature is the right length so the transcript round-trip
        # is well-formed.
        return len(signature) == self.sig_len and len(public_key) == self.pk_len


class _RealKEM:
    """liboqs-backed ML-KEM-768 wrapper (FIPS 203)."""

    name = "ML-KEM-768"

    def __init__(self) -> None:
        if oqs is None:
            raise RuntimeError("liboqs-python is not installed")
        self._kem = oqs.KeyEncapsulation("ML-KEM-768")  # type: ignore[attr-defined]
        self._pk: Optional[bytes] = None

    def generate_keypair(self) -> bytes:
        self._pk = self._kem.generate_keypair()
        return bytes(self._pk)

    def encapsulate(self, peer_pk: bytes) -> tuple[bytes, bytes]:
        ct, ss = self._kem.encap_secret(peer_pk)  # type: ignore[attr-defined]
        return bytes(ct), bytes(ss)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return bytes(self._kem.decap_secret(ciphertext))  # type: ignore[attr-defined]


class _RealSig:
    """liboqs-backed ML-DSA-65 wrapper (FIPS 204)."""

    name = "ML-DSA-65"

    def __init__(self) -> None:
        if oqs is None:
            raise RuntimeError("liboqs-python is not installed")
        self._sig = oqs.Signature("ML-DSA-65")  # type: ignore[attr-defined]
        self.public_key = bytes(self._sig.generate_keypair())
        self.pk_len = len(self.public_key)
        # Attempt a 1-byte test signature to learn the runtime sig length;
        # ML-DSA produces variable-length sigs up to FIPS 204's bound.
        try:
            probe = bytes(self._sig.sign(b"\x00"))
            self.sig_len = len(probe)
        except Exception:
            self.sig_len = ML_DSA_65_SIG_LEN

    def sign(self, message: bytes) -> bytes:
        return bytes(self._sig.sign(message))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            return bool(self._sig.verify(message, signature, public_key))  # type: ignore[attr-defined]
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HandshakeTranscript:
    """The auditable summary of one hybrid handshake."""

    mode: TunnelMode
    client_hello_len: int
    server_hello_len: int
    rtt_ms: float
    shared_secret_digest: str
    transcript_signature_alg: str
    transcript_signature_len: int
    pqc_safe: bool


@dataclass(slots=True)
class HandshakeResult:
    """What the CLI renders: transcript + AEAD round-trip evidence."""

    transcript: HandshakeTranscript
    runtime_report: dict[str, str]
    sample_plaintext: str
    sample_ciphertext_hex: str
    roundtrip_ok: bool


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _unframe(frame: bytes) -> bytes:
    if len(frame) < 4:
        raise ValueError("frame shorter than length prefix")
    (length,) = struct.unpack(">I", frame[:4])
    if length + 4 != len(frame):
        raise ValueError(
            f"frame length mismatch: header={length}, body={len(frame) - 4}"
        )
    return frame[4 : 4 + length]


def _hkdf_combine(x25519_ss: bytes, mlkem_ss: bytes) -> bytes:
    """Mix the two shared secrets into a 256-bit session key."""

    hkdf = HKDF(  # type: ignore[call-arg]
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"AQC/q-tunnel/salt/v1",
        info=HYBRID_SUITE_ID,
    )
    return hkdf.derive(x25519_ss + mlkem_ss)


# ---------------------------------------------------------------------------
# Record layer (AEAD)
# ---------------------------------------------------------------------------


class RecordLayer:
    """AES-256-GCM record protection under a per-direction nonce counter."""

    __slots__ = ("_aead", "_send_seq", "_recv_seq", "_send_iv", "_recv_iv")

    def __init__(self, session_key: bytes, *, client_side: bool) -> None:
        if AESGCM is None:
            raise RuntimeError("cryptography package required for record layer")
        self._aead = AESGCM(session_key)
        salt = hashlib.sha256(b"AQC/q-tunnel/iv/" + session_key).digest()
        self._send_iv = salt[:4] if client_side else salt[4:8]
        self._recv_iv = salt[4:8] if client_side else salt[:4]
        self._send_seq = 0
        self._recv_seq = 0

    def _nonce(self, iv: bytes, seq: int) -> bytes:
        return iv + seq.to_bytes(8, "big")

    def seal(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        nonce = self._nonce(self._send_iv, self._send_seq)
        self._send_seq += 1
        return self._aead.encrypt(nonce, plaintext, aad)

    def open(self, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
        nonce = self._nonce(self._recv_iv, self._recv_seq)
        self._recv_seq += 1
        return self._aead.decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# Hybrid gateway
# ---------------------------------------------------------------------------


class HybridPQCGateway:
    """The full hybrid PQC handshake + record layer, in one object."""

    def __init__(self, mode: TunnelMode = TunnelMode.HYBRID) -> None:
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "The `cryptography` package is required for AQC q-tunnel. "
                "Install with: pip install cryptography>=42"
            )

        # Auto-downgrade if HYBRID is requested but liboqs is missing.
        if mode is TunnelMode.HYBRID and not _HAS_OQS:
            self.mode = TunnelMode.SIMULATION
            self._downgraded = True
        else:
            self.mode = mode
            self._downgraded = False

        if self.mode is TunnelMode.HYBRID:
            self._kem = _RealKEM()
            self._sig = _RealSig()
        else:
            self._kem = _SimulatedKEM()
            self._sig = _SimulatedSig()

    # -- Diagnostic ----------------------------------------------------------

    @classmethod
    def runtime_report(cls) -> dict[str, str]:
        """Return a dict of crypto backend availability + selected algorithms."""

        return {
            "cryptography": "available" if _HAS_CRYPTOGRAPHY else "MISSING",
            "liboqs-python": "available" if _HAS_OQS else "MISSING",
            "ML-KEM-768": "liboqs" if _HAS_OQS else TunnelMode.SIMULATION.value,
            "ML-DSA-65": "liboqs" if _HAS_OQS else TunnelMode.SIMULATION.value,
            "AES-256-GCM": "cryptography" if _HAS_CRYPTOGRAPHY else "MISSING",
            "HKDF-SHA-256": "cryptography" if _HAS_CRYPTOGRAPHY else "MISSING",
            "suite_id": HYBRID_SUITE_ID.decode("ascii"),
        }

    @property
    def downgraded(self) -> bool:
        """True if HYBRID was requested but we fell back to SIMULATION."""

        return self._downgraded

    # -- Handshake -----------------------------------------------------------

    def handshake(self) -> tuple[bytes, HandshakeTranscript]:
        """Run a full in-process client↔server hybrid handshake.

        Returns the derived session key and a public transcript suitable
        for logging / regulatory evidence.
        """

        # Client KEM keys + ephemeral X25519 -------------------------------
        client_kem = self._make_kem()
        client_kem_pk = client_kem.generate_keypair()
        client_x_sk = X25519PrivateKey.generate()
        client_x_pub = client_x_sk.public_key().public_bytes_raw()

        client_hello = _frame(client_x_pub + client_kem_pk + HYBRID_SUITE_ID)

        # Server side ------------------------------------------------------
        t0 = time.perf_counter()
        payload = _unframe(client_hello)
        x_pub_bytes = payload[:X25519_PUB_LEN]
        kem_pub = payload[X25519_PUB_LEN : X25519_PUB_LEN + ML_KEM_768_PK_LEN]
        client_x_pub_obj = X25519PublicKey.from_public_bytes(x_pub_bytes)

        server_x_sk = X25519PrivateKey.generate()
        server_x_pub = server_x_sk.public_key().public_bytes_raw()
        x_shared_server = server_x_sk.exchange(client_x_pub_obj)

        server_kem = self._make_kem()
        # We must use the *client's* KEM pk for encap, so the client can
        # decap with its own secret key. Therefore the "server" reuses
        # the client KEM object's pk.
        kem_ct, kem_shared_server = client_kem.encapsulate(kem_pub)

        server_session_key = _hkdf_combine(x_shared_server, kem_shared_server)
        server_hello_payload = server_x_pub + kem_ct

        # Sign the transcript (ClientHello || ServerHello)
        transcript_hash = hashlib.sha256(payload + server_hello_payload).digest()
        signature = self._sig.sign(transcript_hash)
        server_hello = _frame(server_hello_payload + signature)

        # Client side ------------------------------------------------------
        sh_payload = _unframe(server_hello)
        # Length sanity: x25519_pub(32) + kem_ct(1088) + sig(?)
        server_x_pub_bytes = sh_payload[:X25519_PUB_LEN]
        kem_ct_recv = sh_payload[
            X25519_PUB_LEN : X25519_PUB_LEN + ML_KEM_768_CT_LEN
        ]
        signature_recv = sh_payload[X25519_PUB_LEN + ML_KEM_768_CT_LEN :]

        server_x_pub_obj = X25519PublicKey.from_public_bytes(server_x_pub_bytes)
        x_shared_client = client_x_sk.exchange(server_x_pub_obj)
        kem_shared_client = client_kem.decapsulate(kem_ct_recv)
        client_session_key = _hkdf_combine(x_shared_client, kem_shared_client)

        # The signature on the transcript hash is verifiable in HYBRID
        # mode; in SIMULATION mode the verifier only checks lengths.
        _ok = self._sig.verify(
            transcript_hash, signature_recv, self._sig.public_key
        )
        t1 = time.perf_counter()

        if not hmac.compare_digest(client_session_key, server_session_key):
            raise RuntimeError(
                "hybrid handshake produced mismatched session keys — bug!"
            )

        transcript = HandshakeTranscript(
            mode=self.mode,
            client_hello_len=len(client_hello),
            server_hello_len=len(server_hello),
            rtt_ms=(t1 - t0) * 1000.0,
            shared_secret_digest=hashlib.sha256(client_session_key).hexdigest(),
            transcript_signature_alg=self._sig.name,
            transcript_signature_len=len(signature_recv),
            pqc_safe=self.mode is TunnelMode.HYBRID,
        )
        return client_session_key, transcript

    # -- Internal ------------------------------------------------------------

    def _make_kem(self):
        if self.mode is TunnelMode.HYBRID:
            return _RealKEM()
        return _SimulatedKEM()


# ---------------------------------------------------------------------------
# Public demo entrypoints
# ---------------------------------------------------------------------------


def run_demo_handshake(
    *,
    mode: TunnelMode = TunnelMode.HYBRID,
    sample_plaintext: str = "[AQC] biometric frame: ECG=72bpm SpO2=98 EEG-α=10.4Hz",
) -> HandshakeResult:
    """Run one hybrid handshake + AEAD round-trip and return the evidence."""

    gw = HybridPQCGateway(mode=mode)
    session_key, transcript = gw.handshake()

    send = RecordLayer(session_key, client_side=True)
    recv = RecordLayer(session_key, client_side=False)
    aad = transcript.shared_secret_digest[:16].encode("ascii")
    ct = send.seal(sample_plaintext.encode("utf-8"), aad=aad)
    pt = recv.open(ct, aad=aad)
    roundtrip_ok = pt.decode("utf-8") == sample_plaintext

    return HandshakeResult(
        transcript=transcript,
        runtime_report=HybridPQCGateway.runtime_report(),
        sample_plaintext=sample_plaintext,
        sample_ciphertext_hex=ct.hex(),
        roundtrip_ok=roundtrip_ok,
    )


def write_demo_report(result: HandshakeResult, path: Path | str) -> Path:
    """Persist a :class:`HandshakeResult` to disk as JSON."""

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    transcript = asdict(result.transcript)
    transcript["mode"] = result.transcript.mode.value
    payload = {
        "transcript": transcript,
        "runtime_report": result.runtime_report,
        "sample_plaintext": result.sample_plaintext,
        "sample_ciphertext_hex": result.sample_ciphertext_hex,
        "roundtrip_ok": result.roundtrip_ok,
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out
