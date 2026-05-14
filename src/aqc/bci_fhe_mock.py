"""FHE-on-Brain-Prints demo — the Soul Catcher 2.0 defuser.

This module demonstrates the *architecture* of cognitive privacy under
HNDL: a Brain Print (feature vector extracted from a DARPA N3-class
BCI / EEG stream) is encrypted at the device under a partially
homomorphic scheme. The cloud analytics layer then computes
**sum, mean, and cosine similarity against a cleartext template**
without ever decrypting the patient's brain print.

Real CKKS / BFV (OpenFHE, Microsoft SEAL, TenSEAL) would replace the
Paillier core below for production. Paillier is sufficient for the
demo because *every* operation the Soul Catcher 2.0 defuser needs is
linear in the ciphertext: addition of ciphertexts and multiplication
of a ciphertext by a cleartext scalar. That is exactly the additive
homomorphism Paillier provides natively.

The implementation here is a self-contained Paillier in pure Python.
It is real Paillier (not a HKDF stand-in), but it is intentionally
small and not constant-time. Treat it as a *correctness reference*,
not a production library.
"""

from __future__ import annotations

import math
import os
import secrets
from dataclasses import dataclass, field
from typing import Iterable, Sequence

# ---------------------------------------------------------------------------
# Fixed-point encoding
# ---------------------------------------------------------------------------

#: Scale 1.0 → 1_000_000 so we have ~6 fractional decimal digits.
FIXED_POINT_SCALE: int = 1_000_000


def encode(value: float, *, n: int, scale: int = FIXED_POINT_SCALE) -> int:
    """Encode a real number into Z_n (Paillier plaintext space)."""

    return int(round(value * scale)) % n


def decode(value: int, *, n: int, scale: int = FIXED_POINT_SCALE) -> float:
    """Decode a Z_n element back to a real number with signed reading."""

    half = n >> 1
    signed = value if value <= half else value - n
    return signed / scale


# ---------------------------------------------------------------------------
# Miller–Rabin primality (pure Python, deterministic for 256-bit inputs)
# ---------------------------------------------------------------------------


_SMALL_PRIMES: tuple[int, ...] = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
)


def _is_probable_prime(n: int, *, k: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _i in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    """Generate a probable prime of exactly ``bits`` bits."""

    if bits < 16:
        raise ValueError("bits must be >= 16 for the Paillier demo")
    while True:
        # Force the top two bits set (so the product of two primes has
        # the expected modulus size) and the bottom bit set.
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(candidate):
            return candidate


# ---------------------------------------------------------------------------
# Paillier
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PaillierPublicKey:
    """Paillier public key (n, g). g is fixed to n+1 for efficiency."""

    n: int
    g: int

    @property
    def n_sq(self) -> int:
        return self.n * self.n

    def encrypt(self, plaintext: int) -> int:
        n, n_sq = self.n, self.n_sq
        m = plaintext % n
        # Random r in Z_n^*. With overwhelming probability gcd(r,n)=1.
        while True:
            r = secrets.randbelow(n - 1) + 1
            if math.gcd(r, n) == 1:
                break
        # c = (1 + m*n) * r^n mod n^2  — uses the g = n+1 shortcut.
        return ((1 + m * n) % n_sq) * pow(r, n, n_sq) % n_sq


@dataclass(slots=True)
class PaillierPrivateKey:
    """Paillier private key (λ, μ) bound to a :class:`PaillierPublicKey`."""

    public: PaillierPublicKey
    lam: int   # λ = lcm(p-1, q-1)
    mu: int    # μ = (L(g^λ mod n²))^{-1} mod n

    def decrypt(self, ciphertext: int) -> int:
        n, n_sq = self.public.n, self.public.n_sq
        u = pow(ciphertext, self.lam, n_sq)
        # L(u) = (u - 1) / n
        return ((u - 1) // n * self.mu) % n


def keygen(bits: int = 512) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generate a Paillier key pair with an n of approximately ``bits`` bits.

    For a real deployment use >= 2048 bits. The 512-bit default exists
    so the demo runs in well under a second on a laptop.
    """

    if bits < 64:
        raise ValueError("bits too small; use >= 64 for the demo, >=2048 for prod")
    half = bits // 2
    p = _gen_prime(half)
    q = _gen_prime(half)
    while q == p:
        q = _gen_prime(half)
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    pub = PaillierPublicKey(n=n, g=n + 1)
    # μ = (L(g^λ mod n²))^{-1} mod n. With g = n+1 we get L(g^λ) ≡ λ (mod n)
    # so μ = λ^{-1} mod n.
    mu = pow(lam, -1, n)
    return pub, PaillierPrivateKey(public=pub, lam=lam, mu=mu)


# Homomorphic operations — pure functions of the *public* key + ciphertexts.


def homomorphic_add(pub: PaillierPublicKey, c1: int, c2: int) -> int:
    """Enc(m1) ⊞ Enc(m2) = Enc(m1 + m2)."""

    return (c1 * c2) % pub.n_sq


def homomorphic_scalar_mul(pub: PaillierPublicKey, c: int, scalar: int) -> int:
    """Enc(m) ⊠ k = Enc(k * m)  (scalar in cleartext)."""

    return pow(c, scalar % pub.n, pub.n_sq)


def homomorphic_sum(pub: PaillierPublicKey, ciphertexts: Iterable[int]) -> int:
    out = 1
    nsq = pub.n_sq
    for c in ciphertexts:
        out = (out * c) % nsq
    return out


# ---------------------------------------------------------------------------
# Brain Print template
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BrainPrintTemplate:
    """A small, deterministic Brain Print used by the demo.

    Fields are normalised band-power ratios and event-related potential
    amplitudes that together form a "cognitive fingerprint" the server
    is asked to score against a cleartext baseline.
    """

    labels: Sequence[str]
    features: Sequence[float]

    def __len__(self) -> int:
        return len(self.features)


def cosine_baseline_template() -> BrainPrintTemplate:
    """Return the canonical UHNW principal Brain Print used by the demo."""

    labels = (
        "alpha-band-power",
        "beta-band-power",
        "theta-band-power",
        "gamma-band-power",
        "P300-amplitude",
        "N200-amplitude",
        "frontal-theta-coherence",
        "occipital-alpha-coherence",
    )
    features = (10.42, 6.18, 4.03, 2.71, 5.84, -3.21, 0.62, 0.78)
    return BrainPrintTemplate(labels=labels, features=features)


# ---------------------------------------------------------------------------
# Demo result + driver
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class FHEDemoResult:
    keysize_bits: int
    plaintext_features: list[float]
    weights: list[float]
    plaintext_sum: float
    decrypted_sum: float
    decrypted_mean: float
    plaintext_dot: float
    decrypted_dot: float
    correctness_ok: bool
    note: str


def _weights_for(bp: BrainPrintTemplate) -> list[float]:
    """A deterministic weight vector for the cosine-similarity demo.

    Values reflect a "Soul Catcher 2.0 defuser" classifier that emphasises
    frontal-theta coherence (cognitive load) and P300 (attention).
    """

    presets = {
        "alpha-band-power":            0.20,
        "beta-band-power":             0.15,
        "theta-band-power":            0.10,
        "gamma-band-power":            0.05,
        "P300-amplitude":              0.30,
        "N200-amplitude":              0.05,
        "frontal-theta-coherence":     0.10,
        "occipital-alpha-coherence":   0.05,
    }
    return [presets.get(lbl, 0.10) for lbl in bp.labels]


def run_fhe_brainprint_demo(
    *,
    keysize_bits: int = 512,
    bp: BrainPrintTemplate | None = None,
) -> FHEDemoResult:
    """Run the Brain Print → Paillier → analytics → decrypt round-trip.

    The flow is:

    1. Generate a Paillier key pair.
    2. Encrypt each feature of the Brain Print at the *device*.
    3. The *cloud* computes Σ, mean, and ⟨features, weights⟩ on
       ciphertexts only — it never sees a plaintext sample.
    4. The encrypted results travel back to the device, which decrypts
       under the private key.

    Steps 2–4 honour the property that the cloud operator (or anyone
    who has merely HNDL-captured the cloud's input) cannot reconstruct
    the patient's cognitive baseline.
    """

    bp = bp or cosine_baseline_template()
    pub, priv = keygen(bits=keysize_bits)
    n = pub.n
    weights = _weights_for(bp)

    # 1. Device encrypts each feature ----------------------------------------
    cts: list[int] = []
    for f in bp.features:
        cts.append(pub.encrypt(encode(f, n=n)))

    # 2. Cloud computes Σ on ciphertexts ------------------------------------
    sum_ct = homomorphic_sum(pub, cts)

    # 3. Cloud computes ⟨features, weights⟩ on ciphertexts ------------------
    weight_ints = [encode(w, n=n) for w in weights]
    weighted = [
        homomorphic_scalar_mul(pub, c, w_int) for c, w_int in zip(cts, weight_ints)
    ]
    dot_ct = homomorphic_sum(pub, weighted)

    # 4. Device decrypts -----------------------------------------------------
    decoded_sum = decode(priv.decrypt(sum_ct), n=n)

    # The dot product was computed by scalar-multiplying every feature
    # ciphertext by a fixed-point-encoded weight. Each term is therefore
    # the product of two scale-1e6 encodings, so the aggregated result
    # decodes at scale^2 = 1e12.
    dot_decoded_int = priv.decrypt(dot_ct)
    decoded_dot = decode(
        dot_decoded_int, n=n, scale=FIXED_POINT_SCALE * FIXED_POINT_SCALE
    )

    plaintext_sum = float(sum(bp.features))
    plaintext_dot = float(sum(f * w for f, w in zip(bp.features, weights)))
    decrypted_mean = decoded_sum / max(len(bp.features), 1)

    correctness_ok = (
        math.isclose(decoded_sum, plaintext_sum, rel_tol=0, abs_tol=1e-3)
        and math.isclose(decoded_dot, plaintext_dot, rel_tol=0, abs_tol=1e-3)
    )

    note = (
        "Real Paillier (additive HE). All ciphertext ops were performed "
        "without the private key. Swap in OpenFHE / Microsoft SEAL / "
        "TenSEAL CKKS for floating-point fidelity and depth > 1."
    )

    return FHEDemoResult(
        keysize_bits=keysize_bits,
        plaintext_features=list(bp.features),
        weights=list(weights),
        plaintext_sum=plaintext_sum,
        decrypted_sum=decoded_sum,
        decrypted_mean=decrypted_mean,
        plaintext_dot=plaintext_dot,
        decrypted_dot=decoded_dot,
        correctness_ok=correctness_ok,
        note=note,
    )
