"""Markdown → PDF with optional evaluation watermark (freemium tier)."""

from __future__ import annotations

import re
from html import escape
from pathlib import Path

from aqc.report_pdf import _REPORT_CSS, _utc  # noqa: SLF001 — reuse audited print CSS

_WATERMARK_CSS = """
.aqc-wm-layer {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  overflow: visible;
}
.aqc-wm-layer .aqc-wm-band {
  position: absolute;
  left: -25%;
  width: 150%;
  text-align: center;
  font-size: 42pt;
  font-weight: 900;
  color: rgba(180, 0, 0, 0.22);
  letter-spacing: 0.06em;
  transform: rotate(-32deg);
  white-space: nowrap;
}
.aqc-wm-layer .aqc-wm-band:nth-child(1) { top: 18%; }
.aqc-wm-layer .aqc-wm-band:nth-child(2) { top: 38%; font-size: 28pt; color: rgba(160, 0, 0, 0.18); }
.aqc-wm-layer .aqc-wm-band:nth-child(3) { top: 58%; font-size: 36pt; }
body.aqc-unlicensed main,
body.aqc-unlicensed .cover,
body.aqc-unlicensed .footer-note {
  position: relative;
  z-index: 1;
}
body.aqc-unlicensed .cover .badge {
  background: #991b1b;
  color: #fff;
}
.aqc-licensing-appendix {
  page-break-before: always;
  min-height: 80vh;
  padding: 24pt;
  border: 3pt solid #b91c1c;
  background: #fef2f2;
}
.aqc-licensing-appendix h2 { color: #991b1b; font-size: 18pt; }
.page-break-between { page-break-before: always; }
"""


def _md_to_html_fragment(md: str) -> str:
    import markdown  # type: ignore[import-untyped]

    inner = markdown.markdown(
        md,
        extensions=["tables", "fenced_code", "nl2br", "sane_lists"],
        output_format="html5",
    )
    return re.sub(r"<h1\b[^>]*>.*?</h1>", "", inner, count=1, flags=re.I | re.DOTALL)


def _wrap_compliance_html(
    inner_html: str,
    *,
    document_title: str,
    banner: str,
    is_licensed: bool,
    purchase_url: str,
    second_inner_html: str | None = None,
    second_title: str | None = None,
) -> str:
    title_esc = escape(document_title)
    banner_esc = escape(banner)
    body_cls = "" if is_licensed else "aqc-unlicensed"
    wm_block = ""
    if not is_licensed:
        wm_block = """<div class="aqc-wm-layer" aria-hidden="true">
<div class="aqc-wm-band">UNLICENSED AEGIS EVALUATION</div>
<div class="aqc-wm-band">NOT FOR FDA / DoD SUBMISSION</div>
<div class="aqc-wm-band">DRAFT — REMOVE WATERMARK WITH ENTERPRISE LICENSE</div>
</div>"""
    appendix = ""
    if not is_licensed:
        appendix = f"""
<section class="aqc-licensing-appendix">
<h2>Enterprise license required</h2>
<p style="font-size:12pt;line-height:1.5">
This PDF was generated under the <strong>unlicensed evaluation tier</strong>.
The diagonal markings are rendered into the print stream for compliance awareness.
To obtain a <strong>clean, submission-ready</strong> artifact and operational
support (ML-DSA signing hooks, audit trail, and CBOM governance), purchase an
enterprise license from your Aegis Quantum-Cognitive account team.
</p>
<p style="font-size:12pt"><strong>Purchase / contact:</strong>
<a href="{escape(purchase_url, quote=True)}">{escape(purchase_url)}</a></p>
<p style="font-size:10pt;color:#555">
Regulatory filings require independent legal and quality review. Nothing in this
document constitutes FDA or DoD approval.
</p>
</section>"""
    mid = ""
    if second_inner_html is not None and second_title:
        mid = f"""
<div class="page-break-between"></div>
<h1 style="font-size:16pt;margin-top:0">{escape(second_title)}</h1>
{second_inner_html}
"""
    badge_esc = escape(
        "Official audit artifact"
        if is_licensed
        else "Evaluation only — not for submission"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{title_esc}</title>
  <style>{_REPORT_CSS}{_WATERMARK_CSS}</style>
</head>
<body class="{body_cls}">
{wm_block}
  <div class="cover">
    <h1>{title_esc}</h1>
    <p class="subtitle">{banner_esc}</p>
    <p class="meta">Generated {escape(_utc())} · Aegis Quantum-Cognitive API</p>
    <span class="badge">{badge_esc}</span>
  </div>
  <main>
  {inner_html}
  {mid}
  {appendix}
  </main>
  <p class="footer-note">
    Produced by Aegis Quantum-Cognitive. Heuristic / toolchain output — not a
    substitute for formal design assurance.
  </p>
</body>
</html>"""


def render_compliance_pdf(
    markdown_content: str,
    out_pdf: Path,
    *,
    is_licensed: bool,
    document_title: str = "AQC Compliance Addendum",
    banner: str = "FDA e-STAR / NSM-10 narrative (single document)",
    purchase_url: str = "https://github.com/AAH20/Aegis_Q_Cognitive",
    companion_markdown: str | None = None,
    companion_title: str | None = None,
) -> None:
    """Render Markdown to PDF. When ``is_licensed`` is False, burn in watermark layer."""

    inner = _md_to_html_fragment(markdown_content)
    second = (
        _md_to_html_fragment(companion_markdown)
        if companion_markdown is not None
        else None
    )
    html = _wrap_compliance_html(
        inner,
        document_title=document_title,
        banner=banner,
        is_licensed=is_licensed,
        purchase_url=purchase_url,
        second_inner_html=second,
        second_title=companion_title,
    )
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint required. Install: pip install -e '.[api]' or '.[render]'"
        ) from exc
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(out_pdf.parent.resolve())).write_pdf(str(out_pdf))
