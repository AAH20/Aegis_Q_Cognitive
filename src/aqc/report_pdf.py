"""Convert AQC ``reports/`` artifacts into professionally typeset PDFs.

The pipeline is Markdown / JSON / YAML → HTML5 (with an embedded corporate
stylesheet tuned for WeasyPrint) → PDF.  Pandoc is optional: when it is
on ``$PATH`` it is used for Markdown → HTML (superior GFM table support);
otherwise the ``markdown`` library is used.

Install::

    pip install -e ".[render]"      # weasyprint + markdown
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Stylesheet — tuned for WeasyPrint (print margins + running footers)
# ---------------------------------------------------------------------------

_REPORT_CSS = """
@page {
  size: A4;
  margin: 18mm 16mm 22mm 16mm;
  @top-center {
    content: string(doc-title);
    font-size: 8.5pt;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #1e3a5f;
    border-bottom: 0.5pt solid #c5d0e0;
    width: 100%;
    padding-bottom: 4pt;
    margin-bottom: 6pt;
  }
  @bottom-center {
    content: counter(page) " · " counter(pages);
    font-size: 8.5pt;
    color: #6b7280;
    padding-top: 6pt;
    border-top: 0.5pt solid #e5e7eb;
    width: 30%;
  }
}

@page :first {
  @top-center { content: none; border: none; }
}

:root {
  --ink: #111827;
  --muted: #4b5563;
  --line: #e5e7eb;
  --accent: #1e3a8a;
  --accent-soft: #eef2ff;
  --danger-bg: #fef2f2;
  --danger: #991b1b;
}

* { box-sizing: border-box; }

html {
  font-family: "Helvetica Neue", Helvetica, "Segoe UI", Roboto, Arial, sans-serif;
  font-size: 10.5pt;
  line-height: 1.45;
  color: var(--ink);
}

body {
  margin: 0;
  padding: 0;
}

.cover {
  padding: 12pt 0 20pt 0;
  margin-bottom: 16pt;
  border-bottom: 2pt solid var(--accent);
}

.cover h1 {
  margin: 0 0 4pt 0;
  font-size: 20pt;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: -0.02em;
  string-set: doc-title content(text);
}

.cover .subtitle {
  margin: 0;
  font-size: 11pt;
  color: var(--muted);
  font-weight: 400;
}

.cover .meta {
  margin-top: 10pt;
  font-size: 9pt;
  color: var(--muted);
}

.badge {
  display: inline-block;
  margin-top: 8pt;
  padding: 3pt 8pt;
  font-size: 8pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  background: var(--accent-soft);
  color: var(--accent);
  border-radius: 2pt;
}

main {
  margin-top: 8pt;
}

h1, h2, h3, h4 {
  color: #1e293b;
  page-break-after: avoid;
}
h1 { font-size: 15pt; margin: 18pt 0 8pt; border-bottom: 0.5pt solid var(--line); padding-bottom: 4pt; }
h2 { font-size: 12pt; margin: 16pt 0 6pt; }
h3 { font-size: 11pt; margin: 12pt 0 4pt; }

p { margin: 6pt 0; orphans: 3; widows: 3; }

a { color: var(--accent); text-decoration: none; }

blockquote {
  margin: 10pt 0;
  padding: 8pt 12pt;
  border-left: 3pt solid var(--accent);
  background: #f8fafc;
  color: var(--muted);
  font-size: 9.8pt;
}

code, pre, .mono {
  font-family: "Menlo", "Consolas", "DejaVu Sans Mono", monospace;
  font-size: 8.8pt;
}

pre {
  background: #f9fafb;
  border: 0.5pt solid var(--line);
  border-radius: 3pt;
  padding: 10pt;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 12pt 0;
  font-size: 9.3pt;
  page-break-inside: avoid;
}

thead th {
  background: #1e3a8a;
  color: #fff;
  font-weight: 600;
  text-align: left;
  padding: 7pt 8pt;
  border: none;
}
tbody td {
  padding: 6pt 8pt;
  border-bottom: 0.5pt solid var(--line);
  vertical-align: top;
}
tbody tr:nth-child(even) { background: #fafafa; }

.sev-critical { background: var(--danger-bg); color: var(--danger); font-weight: 700; }
.sev-safe { background: #ecfdf5; color: #065f46; font-weight: 600; }

.footer-note {
  margin-top: 20pt;
  padding-top: 10pt;
  border-top: 0.5pt solid var(--line);
  font-size: 8.5pt;
  color: var(--muted);
}
"""


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _have_pandoc() -> bool:
    return shutil.which("pandoc") is not None


def _md_markdown_lib(src: str) -> str:
    import markdown  # type: ignore[import-untyped]

    return markdown.markdown(
        src,
        extensions=["tables", "fenced_code", "nl2br", "sane_lists"],
        output_format="html5",
    )


def _md_pandoc(path: Path) -> str:
    proc = subprocess.run(
        [
            "pandoc",
            "--from",
            "gfm",
            "--to",
            "html5",
            "--standalone",
            str(path),
        ],
        capture_output=True,
        check=True,
        timeout=90,
    )
    html = proc.stdout.decode("utf-8")
    # Strip pandoc's own html/head/body — we inject our shell.
    lower = html.lower()
    b = lower.find("<body")
    if b == -1:
        return html
    b = html.find(">", b) + 1
    e = lower.rfind("</body>")
    return html[b:e].strip() if e > b else html


def _wrap_document(inner_html: str, *, document_title: str, banner: str) -> str:
    title_esc = escape(document_title)
    banner_esc = escape(banner)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{title_esc}</title>
  <style>{_REPORT_CSS}</style>
</head>
<body>
  <div class="cover">
    <h1>{title_esc}</h1>
    <p class="subtitle">{banner_esc}</p>
    <p class="meta">Generated {_escape(_utc())} · Aegis Quantum-Cognitive</p>
    <span class="badge">Official audit artifact</span>
  </div>
  <main>
  {inner_html}
  </main>
  <p class="footer-note">
    This document was produced by the Aegis Quantum-Cognitive tooling suite.
    Regulatory submissions require independent legal and quality review before filing.
  </p>
</body>
</html>
"""


def _escape(s: str) -> str:
    return escape(s, quote=True)


def _write_pdf(html: str, pdf: Path) -> None:
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint is required for PDF export. Install with: pip install -e '.[render]'"
        ) from exc
    pdf.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(pdf.parent.resolve())).write_pdf(str(pdf))


def markdown_file_to_pdf(md: Path, pdf: Path, *, document_title: str, banner: str) -> None:
    body = md.read_text(encoding="utf-8")
    if _have_pandoc():
        inner = _md_pandoc(md)
    else:
        inner = _md_markdown_lib(body)
    # Pandoc emits the Markdown title as <h1>; the cover sheet already
    # carries the formal document title — drop the duplicate heading.
    inner = re.sub(r"<h1\b[^>]*>.*?</h1>", "", inner, count=1, flags=re.I | re.DOTALL)
    html = _wrap_document(inner, document_title=document_title, banner=banner)
    _write_pdf(html, pdf)


def _table(headers: list[str], rows: list[list[str]], *, sev_col: Optional[int] = None) -> str:
    th = "".join(f"<th>{_escape(h)}</th>" for h in headers)
    body_rows = []
    for r in rows:
        cells = []
        for i, c in enumerate(r):
            cls = ""
            if sev_col is not None and i == sev_col:
                v = c.upper()
                if "CRITICAL" in v or "HIGH" in v:
                    cls = ' class="sev-critical"'
                elif v == "SAFE":
                    cls = ' class="sev-safe"'
            cells.append(f"<td{cls}>{_escape(str(c))}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    return (
        "<table><thead><tr>" + th + "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table>"
    )


def _kv_table(pairs: list[tuple[str, Any]]) -> str:
    rows = [[str(k), str(v)] for k, v in pairs]
    return _table(["Field", "Value"], rows)


def json_cbom_to_html(cbom: dict[str, Any]) -> str:
    parts = []
    meta = cbom.get("metadata") or {}
    comp = (meta.get("component") or {}).get("name", "")
    parts.append(f"<h2>Cryptographic Bill of Materials</h2>")
    parts.append(f"<p><strong>Target system:</strong> {_escape(str(comp))}</p>")
    parts.append(f"<p><strong>CBOM serial:</strong> <code>{_escape(cbom.get('serialNumber',''))}</code></p>")
    rows = []
    for c in cbom.get("components", []) or []:
        ev = c.get("evidence") or {}
        sev = ""
        for p in c.get("properties", []):
            if p.get("name") == "aqc:severity":
                sev = str(p.get("value", ""))
                break
        rows.append(
            [
                str(ev.get("endpoint", "")),
                str(ev.get("device_class", "")),
                str(c.get("name", "")),
                sev,
            ]
        )
    parts.append(_table(["Endpoint", "Device class", "Algorithm", "Severity"], rows, sev_col=3))
    return "\n".join(parts)


def json_hndl_to_html(rows: list[dict[str, Any]]) -> str:
    parts = ["<h2>HNDL / Soul Catcher findings</h2>"]
    table_rows = []
    for f in rows:
        table_rows.append(
            [
                str(f.get("endpoint", "")),
                str(f.get("device_class", "")),
                str(f.get("algorithm", "")),
                str(f.get("severity", "")),
                "Yes" if f.get("soul_catcher_vector") else "—",
            ]
        )
    parts.append(
        _table(
            ["Endpoint", "Device", "Algorithm", "Severity", "Soul Catcher 2.0"],
            table_rows,
            sev_col=3,
        )
    )
    return "\n".join(parts)


def json_handshake_to_html(blob: dict[str, Any]) -> str:
    t = blob.get("transcript") or {}
    parts = [
        "<h2>Hybrid PQC tunnel handshake</h2>",
        _kv_table(
            [
                ("Mode", t.get("mode")),
                ("Quantum-safe", "Yes" if t.get("pqc_safe") else "No (simulation)"),
                ("ClientHello (bytes)", t.get("client_hello_len")),
                ("ServerHello (bytes)", t.get("server_hello_len")),
                (
                    "Round-trip (ms)",
                    f"{t.get('rtt_ms', 0):.3f}" if t.get("rtt_ms") is not None else "—",
                ),
                ("Shared secret (SHA-256)", t.get("shared_secret_digest")),
                ("Signature algorithm", t.get("transcript_signature_alg")),
                ("AEAD round-trip", "OK" if blob.get("roundtrip_ok") else "Failed"),
            ]
        ),
    ]
    if blob.get("sample_plaintext"):
        parts.append("<h3>Sample plaintext frame</h3>")
        parts.append(f"<pre>{_escape(str(blob['sample_plaintext']))}</pre>")
    return "\n".join(parts)


def json_fhe_to_html(blob: dict[str, Any]) -> str:
    kv_pairs: list[tuple[str, Any]] = []
    for k in (
        "keysize_bits",
        "plaintext_sum",
        "decrypted_sum",
        "decrypted_mean",
        "plaintext_dot",
        "decrypted_dot",
        "correctness_ok",
    ):
        if k in blob:
            kv_pairs.append((k, blob[k]))
    parts = ["<h2>Homomorphic Brain Print analysis</h2>", _kv_table(kv_pairs)]
    if blob.get("labels"):
        parts.append("<h3>Features</h3>")
        labs = blob["labels"]
        pf = blob.get("plaintext_features") or []
        w = blob.get("weights") or []
        rows = [
            [
                str(lab),
                str(pf[i]) if i < len(pf) else "",
                str(w[i]) if i < len(w) else "",
            ]
            for i, lab in enumerate(labs)
        ]
        parts.append(_table(["Feature", "Value", "Weight"], rows))
    return "\n".join(parts)


def yaml_policy_to_html(text: str) -> str:
    return (
        "<h2>JADC2 segmentation policy</h2>"
        "<p>Machine-readable YAML as captured from <code>aqc generate-jadc2-policy</code>.</p>"
        f"<pre class='mono'>{_escape(text)}</pre>"
    )


def render_reports_dir(
    directory: Path | str,
) -> dict[str, str]:
    """Render every supported report under ``directory`` to PDF.

    Returns a map of output PDF stem → ``\"ok\"`` or an error message.
    """

    d = Path(directory)
    out: dict[str, str] = {}

    pairs = [
        (d / "fda-estar-cyber-addendum.md", d / "fda-estar-cyber-addendum.pdf", "FDA e-STAR Cybersecurity Addendum", "Premarket cybersecurity RTA-aligned narrative"),
        (d / "dod-nsm10-pqc-roadmap.md", d / "dod-nsm10-pqc-roadmap.pdf", "DoD NSM-10 PQC Transition Roadmap", "CNSA 2.0 migration schedule and per-asset gates"),
    ]
    for md, pdf, title, banner in pairs:
        if md.is_file():
            try:
                markdown_file_to_pdf(md, pdf, document_title=title, banner=banner)
                out[pdf.name] = "ok"
            except Exception as exc:  # pragma: no cover
                out[pdf.name] = str(exc)

    cbom = d / "cbom.json"
    if cbom.is_file():
        try:
            data = json.loads(cbom.read_text(encoding="utf-8"))
            inner = json_cbom_to_html(data)
            html = _wrap_document(
                inner,
                document_title="Cryptographic Bill of Materials (CBOM)",
                banner="CycloneDX 1.6 extract · neural & biometric transport surface",
            )
            _write_pdf(html, d / "cbom-report.pdf")
            out["cbom-report.pdf"] = "ok"
        except Exception as exc:
            out["cbom-report.pdf"] = str(exc)

    hndl = d / "hndl-findings.json"
    if hndl.is_file():
        try:
            rows = json.loads(hndl.read_text(encoding="utf-8"))
            inner = json_hndl_to_html(rows)
            html = _wrap_document(
                inner,
                document_title="HNDL / Soul Catcher Audit Report",
                banner="Data-in-transit exposure assessment",
            )
            _write_pdf(html, d / "hndl-findings-report.pdf")
            out["hndl-findings-report.pdf"] = "ok"
        except Exception as exc:
            out["hndl-findings-report.pdf"] = str(exc)

    pol = d / "jadc2-segmentation.yaml"
    if pol.is_file():
        try:
            inner = yaml_policy_to_html(pol.read_text(encoding="utf-8"))
            html = _wrap_document(
                inner,
                document_title="JADC2 Quantum-Safe Segmentation Policy",
                banner="Identity-first microsegmentation reference design",
            )
            _write_pdf(html, d / "jadc2-segmentation.pdf")
            out["jadc2-segmentation.pdf"] = "ok"
        except Exception as exc:
            out["jadc2-segmentation.pdf"] = str(exc)

    qt = d / "q-tunnel-handshake.json"
    if qt.is_file():
        try:
            blob = json.loads(qt.read_text(encoding="utf-8"))
            inner = json_handshake_to_html(blob)
            html = _wrap_document(
                inner,
                document_title="PQC Tunnel Handshake Evidence",
                banner="ML-KEM-768 + X25519 hybrid KEX transcript",
            )
            _write_pdf(html, d / "q-tunnel-handshake.pdf")
            out["q-tunnel-handshake.pdf"] = "ok"
        except Exception as exc:
            out["q-tunnel-handshake.pdf"] = str(exc)

    fhe = d / "fhe-brainprint-demo.json"
    if fhe.is_file():
        try:
            blob = json.loads(fhe.read_text(encoding="utf-8"))
            inner = json_fhe_to_html(blob)
            html = _wrap_document(
                inner,
                document_title="Brain Print Homomorphic Analysis",
                banner="Paillier ciphertext statistics · Soul Catcher defuser demo",
            )
            _write_pdf(html, d / "fhe-brainprint-demo.pdf")
            out["fhe-brainprint-demo.pdf"] = "ok"
        except Exception as exc:
            out["fhe-brainprint-demo.pdf"] = str(exc)

    return out
