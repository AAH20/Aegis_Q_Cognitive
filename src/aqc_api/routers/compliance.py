"""Compliance generation HTTP API."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from aqc.cbom_generator import dump_cbom, generate_cbom, scan_assets
from aqc.compliance_compiler import (
    load_bundle_from_disk as load_bundle,
)
from aqc.compliance_compiler import (
    render_dod_nsm10,
    render_fda_estar,
)
from aqc.hndl_analyzer import HNDLAnalyzer, synthetic_samples
from aqc_api.services.pdf_engine import render_compliance_pdf

router = APIRouter()


def _hndl_to_json(findings: list) -> list[dict]:
    serialised: list[dict] = []
    for f in findings:
        rec = asdict(f)
        rec["device_class"] = f.device_class.value
        rec["severity"] = f.severity.value
        rec["detected_at"] = f.detected_at.isoformat()
        serialised.append(rec)
    return serialised


def _is_cbom_payload(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get("bomFormat") == "CycloneDX":
        return True
    return "components" in data and isinstance(data.get("components"), list)


def _unlink_tree(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def _license_ok(key: str | None) -> bool:
    if not key:
        return False
    allowed = {
        x.strip()
        for x in os.environ.get("AQC_API_LICENSE_KEYS", "").split(",")
        if x.strip()
    }
    return key in allowed


@router.post(
    "/generate-compliance",
    summary="Generate FDA / NSM-10 compliance PDF from PCAP or CycloneDX CBOM",
    response_class=FileResponse,
)
async def generate_compliance(
    file: Annotated[UploadFile, File(description="PCAP/PCAPNG or CycloneDX cbom.json")],
    license_key: Annotated[
        str | None,
        Query(description="Enterprise key (set AQC_API_LICENSE_KEYS on server)."),
    ] = None,
) -> FileResponse:
    """Run AQC ingest → FDA e-STAR + DoD NSM-10 Markdown → single PDF."""

    name = (file.filename or "upload").lower()
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty upload.")

    is_licensed = _license_ok(license_key)
    purchase_url = os.environ.get(
        "AQC_API_ENTERPRISE_URL",
        "https://github.com/AAH20/Aegis_Q_Cognitive",
    )

    with tempfile.TemporaryDirectory(prefix="aqc-api-") as td:
        tdir = Path(td)
        cbom_path = tdir / "cbom.json"
        hndl_path = tdir / "hndl-findings.json"
        hndl_for_load: Path | None = None

        if name.endswith((".pcap", ".pcapng", ".cap")):
            cap = tdir / "capture.pcap"
            cap.write_bytes(raw)
            assets = scan_assets(cap)
            dump_cbom(generate_cbom(assets, target="aqc-api-upload"), cbom_path)
            samples = synthetic_samples(assets)
            findings = HNDLAnalyzer().analyze(samples)
            hndl_path.write_text(
                json.dumps(_hndl_to_json(findings), indent=2), encoding="utf-8"
            )
            hndl_for_load = hndl_path
        elif name.endswith(".json"):
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise HTTPException(
                    status_code=400, detail=f"Invalid JSON: {e}"
                ) from e
            if not _is_cbom_payload(payload):
                raise HTTPException(
                    status_code=400,
                    detail="JSON must be a CycloneDX-style CBOM (bomFormat + components).",
                )
            cbom_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            raise HTTPException(
                status_code=400,
                detail="Upload a .pcap/.pcapng or CycloneDX .json CBOM.",
            )

        bundle = load_bundle(cbom_path, hndl_for_load)
        fda_md = render_fda_estar(bundle)
        dod_md = render_dod_nsm10(bundle)

        out_pdf = tdir / "aegis-compliance-pack.pdf"
        render_compliance_pdf(
            fda_md,
            out_pdf,
            is_licensed=is_licensed,
            document_title="Aegis Compliance Pack (FDA e-STAR + NSM-10)",
            banner="Combined premarket cybersecurity + PQC transition narrative",
            purchase_url=purchase_url,
            companion_markdown=dod_md,
            companion_title="DoD NSM-10 PQC Transition Roadmap",
        )

        # Copy out to a new temp file so FileResponse can read after ctx exit
        final_dir = tempfile.mkdtemp(prefix="aqc-api-out-")
        final_pdf = Path(final_dir) / "aegis-compliance-pack.pdf"
        final_pdf.write_bytes(out_pdf.read_bytes())

    return FileResponse(
        path=str(final_pdf),
        media_type="application/pdf",
        filename="aegis-compliance-pack.pdf",
        background=BackgroundTask(_unlink_tree, final_dir),
    )
