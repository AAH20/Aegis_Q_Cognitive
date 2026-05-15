"""Tests for the MedTech CI static gate (`ci_cd_auditor`)."""

from __future__ import annotations

from pathlib import Path

from aqc.ci_cd_auditor import audit_repo, main


def test_ci_gate_fails_on_ble_rsa_without_pqc(tmp_path: Path) -> None:
    src = tmp_path / "wearable" / "ble_hr.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "# BLE heart-rate peripheral\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def key(): return rsa.generate_private_key(65537, 2048, None)\n",
        encoding="utf-8",
    )
    v = audit_repo(tmp_path, exclude_prefixes=[], extensions=frozenset({".py"}))
    assert len(v) == 1
    assert v[0]["path"] == "wearable/ble_hr.py"


def test_ci_gate_passes_when_liboqs_present(tmp_path: Path) -> None:
    src = tmp_path / "neural" / "stream.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "import oqs\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "# hybrid lab only — oqs present\n",
        encoding="utf-8",
    )
    v = audit_repo(tmp_path, exclude_prefixes=[], extensions=frozenset({".py"}))
    assert not v


def test_ci_gate_ignores_non_bio_utils(tmp_path: Path) -> None:
    src = tmp_path / "utils" / "crypto_util.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n",
        encoding="utf-8",
    )
    v = audit_repo(tmp_path, exclude_prefixes=[], extensions=frozenset({".py"}))
    assert not v


def test_ci_gate_passes_hybrid_tunnel_shape(tmp_path: Path) -> None:
    src = tmp_path / "gateway" / "q_tunnel_lab.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        'sample = "[AQC] biometric frame: ECG=72"\n'
        "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\n"
        "# ML-KEM hybrid transcript\n",
        encoding="utf-8",
    )
    v = audit_repo(tmp_path, exclude_prefixes=[], extensions=frozenset({".py"}))
    assert not v


def test_main_exit_code_match(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "# eeg\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n",
        encoding="utf-8",
    )
    assert main([str(tmp_path)]) == 1
    (tmp_path / "bad.py").unlink()
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 0
