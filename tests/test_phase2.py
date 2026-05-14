"""Smoke + property tests for the AQC Phase-2 modules.

These tests intentionally cover the *contract* the CLI relies on plus
the cryptographic correctness properties of the Paillier scheme and
the hybrid PQC handshake. They are deterministic and run in well under
five seconds on a stock laptop.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from aqc.cbom_generator import dump_cbom, generate_cbom, scan_assets
from aqc.compliance_compiler import (
    ComplianceBundle,
    SubmissionMetadata,
    load_bundle_from_disk,
    render_dod_nsm10,
    render_fda_estar,
    summarise_bundle,
    write_compliance_pack,
)
from aqc.q_tunnel_gateway import (
    HybridPQCGateway,
    RecordLayer,
    TunnelMode,
    run_demo_handshake,
    write_demo_report,
)
from aqc.bci_fhe_mock import (
    FIXED_POINT_SCALE,
    BrainPrintTemplate,
    cosine_baseline_template,
    decode,
    encode,
    homomorphic_add,
    homomorphic_scalar_mul,
    homomorphic_sum,
    keygen,
    run_fhe_brainprint_demo,
)


# ---------------------------------------------------------------------------
# compliance_compiler
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cbom_dict() -> dict:
    assets = scan_assets(seed=1)
    return generate_cbom(assets, target="phase2-unit-test")


@pytest.fixture(scope="module")
def reports_dir(tmp_path_factory, cbom_dict) -> Path:
    out = tmp_path_factory.mktemp("aqc_reports")
    dump_cbom(cbom_dict, out / "cbom.json")
    (out / "hndl-findings.json").write_text("[]", encoding="utf-8")
    return out


def test_load_bundle_round_trips_metadata(reports_dir: Path) -> None:
    bundle = load_bundle_from_disk(
        reports_dir / "cbom.json",
        reports_dir / "hndl-findings.json",
        sponsor="Acme Bio",
        device_trade_name="Cortex-X",
        fda_submission_type="De Novo",
        contract_vehicle="JADC2",
    )
    assert isinstance(bundle.metadata, SubmissionMetadata)
    assert bundle.metadata.sponsor == "Acme Bio"
    assert bundle.metadata.device_trade_name == "Cortex-X"
    assert bundle.cbom_serial.startswith("urn:aqc:")
    assert bundle.components, "bundle should expose CBOM components"


def test_summarise_bundle_returns_cli_contract(reports_dir: Path) -> None:
    bundle = load_bundle_from_disk(
        reports_dir / "cbom.json", reports_dir / "hndl-findings.json"
    )
    summary = summarise_bundle(bundle)
    for key in ("doc_id", "assets", "critical", "safe", "soul_catcher_vectors"):
        assert key in summary
    assert summary["assets"] == len(bundle.components)
    assert summary["critical"] >= 1
    assert summary["safe"] >= 1


def test_render_fda_estar_contains_required_sections(reports_dir: Path) -> None:
    bundle = load_bundle_from_disk(
        reports_dir / "cbom.json", reports_dir / "hndl-findings.json"
    )
    md = render_fda_estar(bundle)
    for marker in (
        "FDA e-STAR Cybersecurity Addendum",
        "## 1. Executive Summary",
        "## 5. Cryptographic Bill of Materials",
        "## 9. Post-Quantum Cryptography Transition Plan",
        "## 12. Bidirectional Stimulation Safety",
        "ML-KEM-768",
        "ML-DSA-65",
    ):
        assert marker in md, f"missing required section marker: {marker}"


def test_render_dod_nsm10_includes_cnsa_calendar(reports_dir: Path) -> None:
    bundle = load_bundle_from_disk(reports_dir / "cbom.json")
    md = render_dod_nsm10(bundle)
    for marker in (
        "DoD NSM-10 PQC Transition Roadmap",
        "CNSA 2.0",
        "Per-Asset Migration Plan",
        "Procurement Language",
        "## Appendix — Device Class:",
    ):
        assert marker in md, f"missing NSM-10 marker: {marker}"


def test_write_compliance_pack_emits_markdown(reports_dir: Path, tmp_path) -> None:
    bundle = load_bundle_from_disk(reports_dir / "cbom.json")
    out = write_compliance_pack(
        bundle, tmp_path / "pack", render_html=False, render_pdf=False
    )
    assert "fda_estar" in out and "dod_nsm10" in out
    for p in (out["fda_estar"], out["dod_nsm10"]):
        assert p.exists()
        assert p.read_text(encoding="utf-8").strip(), "compliance file is empty"


# ---------------------------------------------------------------------------
# q_tunnel_gateway
# ---------------------------------------------------------------------------


def test_runtime_report_includes_required_capabilities() -> None:
    report = HybridPQCGateway.runtime_report()
    for key in (
        "cryptography",
        "liboqs-python",
        "ML-KEM-768",
        "ML-DSA-65",
        "AES-256-GCM",
        "HKDF-SHA-256",
    ):
        assert key in report


def test_simulation_handshake_roundtrips() -> None:
    result = run_demo_handshake(mode=TunnelMode.SIMULATION)
    t = result.transcript
    assert t.mode is TunnelMode.SIMULATION
    assert t.client_hello_len > 0
    assert t.server_hello_len > 0
    assert result.roundtrip_ok, "AEAD round-trip must succeed"
    assert t.pqc_safe is False
    assert "(SIMULATION)" in t.transcript_signature_alg


def test_simulation_session_key_is_deterministic_between_client_and_server() -> None:
    gw = HybridPQCGateway(mode=TunnelMode.SIMULATION)
    session_key, transcript = gw.handshake()
    assert len(session_key) == 32, "session key should be 256 bits"
    # Encrypt-then-decrypt with two RecordLayer instances sharing the key.
    send = RecordLayer(session_key, client_side=True)
    recv = RecordLayer(session_key, client_side=False)
    aad = transcript.shared_secret_digest[:16].encode()
    ct = send.seal(b"hello aqc", aad=aad)
    assert recv.open(ct, aad=aad) == b"hello aqc"


def test_write_demo_report_persists_json(tmp_path: Path) -> None:
    result = run_demo_handshake(mode=TunnelMode.SIMULATION)
    path = write_demo_report(result, tmp_path / "tunnel.json")
    blob = json.loads(path.read_text(encoding="utf-8"))
    assert blob["transcript"]["mode"] == "SIMULATION"
    assert blob["roundtrip_ok"] is True
    assert "shared_secret_digest" in blob["transcript"]


# ---------------------------------------------------------------------------
# bci_fhe_mock
# ---------------------------------------------------------------------------


def test_paillier_encryption_decryption_roundtrip() -> None:
    pub, priv = keygen(bits=256)
    for plain in (0, 1, 42, 12345, pub.n - 1):
        c = pub.encrypt(plain)
        assert priv.decrypt(c) == plain


def test_paillier_homomorphic_addition() -> None:
    pub, priv = keygen(bits=256)
    a, b = 1234, 5678
    c1 = pub.encrypt(a)
    c2 = pub.encrypt(b)
    c_sum = homomorphic_add(pub, c1, c2)
    assert priv.decrypt(c_sum) == (a + b) % pub.n


def test_paillier_homomorphic_scalar_multiplication() -> None:
    pub, priv = keygen(bits=256)
    a, k = 314, 17
    c = pub.encrypt(a)
    assert priv.decrypt(homomorphic_scalar_mul(pub, c, k)) == (a * k) % pub.n


def test_paillier_homomorphic_sum_matches_decrypt_sum() -> None:
    pub, priv = keygen(bits=256)
    values = [11, 22, 33, 44, 55]
    cts = [pub.encrypt(v) for v in values]
    assert priv.decrypt(homomorphic_sum(pub, cts)) == sum(values) % pub.n


def test_fixed_point_codec_roundtrip() -> None:
    pub, _priv = keygen(bits=256)
    for v in (-1.5, 0.0, 0.123456, 999.5):
        enc = encode(v, n=pub.n)
        dec = decode(enc, n=pub.n)
        assert math.isclose(dec, v, abs_tol=1e-6), f"round-trip failed for {v}"


def test_brainprint_demo_is_correct() -> None:
    bp = cosine_baseline_template()
    assert isinstance(bp, BrainPrintTemplate)
    assert len(bp.features) == len(bp.labels) == 8

    result = run_fhe_brainprint_demo(keysize_bits=512, bp=bp)
    assert result.correctness_ok, (
        f"sum/dot mismatch: sum={result.plaintext_sum}/{result.decrypted_sum} "
        f"dot={result.plaintext_dot}/{result.decrypted_dot}"
    )
    expected_sum = sum(bp.features)
    assert math.isclose(result.decrypted_sum, expected_sum, abs_tol=1e-3)
    expected_dot = sum(f * w for f, w in zip(bp.features, result.weights))
    assert math.isclose(result.decrypted_dot, expected_dot, abs_tol=1e-3)
