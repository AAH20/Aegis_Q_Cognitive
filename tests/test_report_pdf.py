"""Smoke test for PDF report rendering (optional WeasyPrint)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("weasyprint", reason="weasyprint not installed")

from aqc.report_pdf import markdown_file_to_pdf, render_reports_dir


def test_markdown_file_to_pdf_tmp(tmp_path: Path) -> None:
    md = tmp_path / "sample.md"
    md.write_text("# Hello\n\n| a | b |\n|---|---|\n| 1 | 2 |\n", encoding="utf-8")
    pdf = tmp_path / "out.pdf"
    markdown_file_to_pdf(md, pdf, document_title="Sample", banner="Unit test")
    assert pdf.is_file()
    assert pdf.stat().st_size > 500


def test_render_reports_dir_minimal(tmp_path: Path) -> None:
    (tmp_path / "cbom.json").write_text(
        '{"serialNumber":"urn:test","metadata":{"component":{"name":"x"}},'
        '"components":[{"name":"RSA","evidence":{"endpoint":"a:1","device_class":"BCI"},'
        '"properties":[{"name":"aqc:severity","value":"CRITICAL"}]}]}',
        encoding="utf-8",
    )
    r = render_reports_dir(tmp_path)
    assert r.get("cbom-report.pdf") == "ok"
