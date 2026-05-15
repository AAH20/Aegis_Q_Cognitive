"""Smoke tests for the optional FastAPI tier (``[api]`` extra)."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("weasyprint")

from starlette.testclient import TestClient

from aqc.cbom_generator import generate_cbom, scan_assets
from aqc_api.main import app


def test_healthz() -> None:
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_generate_compliance_json_returns_pdf() -> None:
    client = TestClient(app)
    assets = scan_assets(seed=2)
    cbom = generate_cbom(assets, target="api-test")
    body = json.dumps(cbom).encode("utf-8")
    r = client.post(
        "/api/v1/generate-compliance",
        files={"file": ("fleet.json", body, "application/json")},
    )
    assert r.status_code == 200
    assert "application/pdf" in r.headers.get("content-type", "")
    assert r.content.startswith(b"%PDF")


def test_generate_compliance_licensed_no_watermark_css_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Licensed responses still return PDF; tier is controlled server-side via env."""

    monkeypatch.setenv("AQC_API_LICENSE_KEYS", "test-secret-key")
    client = TestClient(app)
    assets = scan_assets(seed=3)
    cbom = generate_cbom(assets, target="api-test-lic")
    body = json.dumps(cbom).encode("utf-8")
    r = client.post(
        "/api/v1/generate-compliance",
        files={"file": ("fleet.json", body, "application/json")},
        params={"license_key": "test-secret-key"},
    )
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF")
