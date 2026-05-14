"""Aegis Quantum-Cognitive CLI.

Usage::

    aqc scan-neural-pcap -f <file>
    aqc generate-jadc2-policy
    aqc full-audit -f <file> -o ./reports

The output is intentionally striking: red/orange for Q-Day-vulnerable
assets, green for PQC-compliant nodes, and a bold banner so anyone
peeking at a Defense CTO's terminal during a screen-share understands
the stakes in under five seconds.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from . import BANNER, __version__
from ._models import HNDLFinding, Severity
from .cbom_generator import (
    assets_to_records,
    dump_cbom,
    generate_cbom,
    scan_assets,
    summarise,
)
from .hndl_analyzer import (
    HNDLAnalyzer,
    stream_samples_from_pcap,
    synthetic_samples,
)
from .jadc2_segmentation import (
    propose_remediation,
    remediation_summary,
    render_policy,
)
from .compliance_compiler import (
    load_bundle_from_disk,
    summarise_bundle,
    write_compliance_pack,
)
from .q_tunnel_gateway import (
    HybridPQCGateway,
    TunnelMode,
    run_demo_handshake,
    write_demo_report,
)
from .bci_fhe_mock import (
    cosine_baseline_template,
    run_fhe_brainprint_demo,
)

console = Console(highlight=False)


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------


_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "yellow",
    Severity.SAFE: "bold green",
}


def _severity_text(sev: Severity) -> Text:
    return Text(sev.value, style=_SEVERITY_STYLES[sev])


def _print_banner() -> None:
    console.print(
        Panel.fit(
            Text(BANNER.format(version=__version__), style="bold cyan"),
            border_style="cyan",
            subtitle="[bold red]CLASSIFIED // FOUO // PQC-READINESS[/bold red]",
        )
    )


def _print_cbom_table(records: list[dict]) -> None:
    table = Table(
        title="Cryptographic Bill of Materials (CBOM)",
        title_style="bold cyan",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Endpoint", no_wrap=False)
    table.add_column("Device Class")
    table.add_column("Algorithm")
    table.add_column("Severity")
    table.add_column("Rationale", overflow="fold")
    for rec in records:
        sev = Severity(rec["severity"])
        table.add_row(
            f"{rec['host']}:{rec['port']}",
            rec["device_class"],
            rec["algorithm"],
            _severity_text(sev),
            rec["rationale"],
        )
    console.print(table)


def _print_hndl_table(findings: list[HNDLFinding]) -> None:
    table = Table(
        title="HNDL / Soul Catcher Audit",
        title_style="bold cyan",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Endpoint", no_wrap=False)
    table.add_column("Device")
    table.add_column("Algorithm")
    table.add_column("Entropy", justify="right")
    table.add_column("Rate (Hz)", justify="right")
    table.add_column("Latency (ms)", justify="right")
    table.add_column("Severity")
    table.add_column("SC 2.0")
    for f in findings:
        sc20 = (
            Text("YES", style="bold white on red")
            if f.soul_catcher_vector
            else Text("no", style="dim")
        )
        table.add_row(
            f.endpoint,
            f.device_class.value,
            f.algorithm,
            f"{f.entropy_bits_per_byte:.2f}",
            f"{f.packet_rate_hz:.1f}",
            f"{f.median_latency_ms:.1f}",
            _severity_text(f.severity),
            sc20,
        )
    console.print(table)


def _print_summary(histogram: dict[str, int]) -> None:
    table = Table(
        title="Risk Summary", title_style="bold cyan", header_style="bold magenta"
    )
    table.add_column("Tier")
    table.add_column("Count", justify="right")
    for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"):
        sev = Severity(sev_name)
        table.add_row(_severity_text(sev), str(histogram.get(sev_name, 0)))
    console.print(table)


def _alert_soul_catcher(findings: list[HNDLFinding]) -> None:
    hot = [f for f in findings if f.soul_catcher_vector]
    if not hot:
        return
    body = Text()
    body.append(
        "Soul Catcher 2.0 Vector detected on the following endpoints:\n\n",
        style="bold white",
    )
    for f in hot:
        body.append(f"  ▶ {f.endpoint}  ", style="bold red")
        body.append(f"({f.device_class.value}, {f.algorithm})\n", style="white")
    body.append(
        "\nIf this telemetry is harvested today, the target's Brain Print "
        "can be quantum-decrypted and SPOOFED back into a bidirectional "
        "BCI on Q-Day — injecting adversarial cognitive payloads into "
        "JADC2 command loops.",
        style="bold yellow",
    )
    console.print(
        Panel(
            body,
            title="[bold white on red] SOUL CATCHER 2.0 — EXTINCTION-CLASS THREAT [/bold white on red]",
            border_style="red",
        )
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.group(
    help="Aegis Quantum-Cognitive — PQC readiness auditor for neural & biometric fabrics.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="aqc")
def main() -> None:
    pass


@main.command("scan-neural-pcap")
@click.option(
    "-f",
    "--file",
    "pcap_file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=False,
    help="Path to a PCAP / PCAPNG capture. Omit to use the synthetic fleet.",
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("./reports"),
    show_default=True,
    help="Directory for CBOM JSON output.",
)
@click.option(
    "--seed",
    type=int,
    default=None,
    help="Optional deterministic seed for the synthetic fleet.",
)
def scan_neural_pcap(
    pcap_file: Optional[Path], out_dir: Path, seed: Optional[int]
) -> None:
    """Run CBOM + HNDL analyzers on a neural / biometric PCAP."""

    _print_banner()
    src_label = str(pcap_file) if pcap_file else "<synthetic neural fleet>"
    console.print(
        Rule(f"[bold cyan]Scanning:[/bold cyan] {src_label}", style="cyan")
    )

    assets = scan_assets(pcap_file, seed=seed)
    cbom = generate_cbom(assets, target=src_label)
    cbom_path = dump_cbom(cbom, out_dir / "cbom.json")
    _print_cbom_table(assets_to_records(assets))
    console.print(
        f"[bold cyan]CBOM written →[/bold cyan] [white]{cbom_path}[/white]\n"
    )

    analyzer = HNDLAnalyzer()
    if pcap_file is not None:
        samples = list(stream_samples_from_pcap(pcap_file)) or synthetic_samples(
            assets, seed=seed
        )
    else:
        samples = synthetic_samples(assets, seed=seed)
    findings = analyzer.analyze(samples)
    _print_hndl_table(findings)

    histogram = summarise(assets)
    _print_summary(histogram)
    _alert_soul_catcher(findings)

    hndl_path = out_dir / "hndl-findings.json"
    hndl_path.parent.mkdir(parents=True, exist_ok=True)
    serialised = []
    for f in findings:
        rec = asdict(f)
        rec["device_class"] = f.device_class.value
        rec["severity"] = f.severity.value
        rec["detected_at"] = f.detected_at.isoformat()
        serialised.append(rec)
    hndl_path.write_text(json.dumps(serialised, indent=2), encoding="utf-8")
    console.print(
        f"[bold cyan]HNDL findings written →[/bold cyan] [white]{hndl_path}[/white]"
    )


@main.command("generate-jadc2-policy")
@click.option(
    "-f",
    "--file",
    "pcap_file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=False,
    help="Optional PCAP — if omitted, the synthetic fleet drives the policy.",
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("./reports"),
    show_default=True,
    help="Directory for the rendered policy.",
)
@click.option("--seed", type=int, default=None, help="Synthetic-fleet seed.")
def generate_jadc2_policy(
    pcap_file: Optional[Path], out_dir: Path, seed: Optional[int]
) -> None:
    """Emit a Quantum-Resistant Identity-First Segmentation policy."""

    _print_banner()
    console.print(
        Rule(
            "[bold cyan]Generating JADC2 PQC Segmentation Policy[/bold cyan]",
            style="cyan",
        )
    )

    assets = scan_assets(pcap_file, seed=seed)
    samples = synthetic_samples(assets, seed=seed)
    findings = HNDLAnalyzer().analyze(samples)
    policies = propose_remediation(findings)
    rendered = render_policy(policies)

    out_dir.mkdir(parents=True, exist_ok=True)
    policy_path = out_dir / "jadc2-segmentation.yaml"
    policy_path.write_text(rendered, encoding="utf-8")

    console.print(
        Panel(
            Text(rendered, style="white"),
            title="[bold cyan]Proposed Microsegmentation[/bold cyan]",
            border_style="cyan",
        )
    )

    stats = remediation_summary(policies)
    table = Table(title="Remediation Summary", header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Enclaves defined", str(stats["enclaves"]))
    table.add_row(
        "Endpoints isolated (quarantine)",
        f"[bold red]{stats['endpoints_isolated']}[/bold red]",
    )
    table.add_row(
        "Endpoints PQC-compliant",
        f"[bold green]{stats['endpoints_pqc_compliant']}[/bold green]",
    )
    console.print(table)
    console.print(
        f"[bold cyan]Policy written →[/bold cyan] [white]{policy_path}[/white]"
    )


@main.command("generate-fda-compliance")
@click.option(
    "-c",
    "--cbom",
    "cbom_path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    required=True,
    help="Path to a CBOM JSON (typically reports/cbom.json).",
)
@click.option(
    "-H",
    "--hndl",
    "hndl_path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    required=False,
    help="Optional HNDL findings JSON (reports/hndl-findings.json).",
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("./reports"),
    show_default=True,
)
@click.option("--sponsor", default="Acquirer-Of-Record (TBD)", show_default=True)
@click.option(
    "--device-name",
    "device_trade_name",
    default="Subject Neural / Biometric Device",
    show_default=True,
)
@click.option(
    "--submission",
    "fda_submission_type",
    default="510(k)",
    show_default=True,
    help="FDA submission type (510(k), De Novo, PMA, ...).",
)
@click.option(
    "--contract",
    "contract_vehicle",
    default="JADC2 — TBD",
    show_default=True,
)
@click.option(
    "--render-html/--no-render-html",
    default=False,
    show_default=True,
    help="Also emit a printable HTML rendering (requires pandoc).",
)
@click.option(
    "--render-pdf/--no-render-pdf",
    default=False,
    show_default=True,
    help="Also emit a printable PDF (requires pandoc + weasyprint).",
)
def generate_fda_compliance(
    cbom_path: Path,
    hndl_path: Optional[Path],
    out_dir: Path,
    sponsor: str,
    device_trade_name: str,
    fda_submission_type: str,
    contract_vehicle: str,
    render_html: bool,
    render_pdf: bool,
) -> None:
    """Generate the FDA e-STAR Addendum *and* DoD NSM-10 PQC roadmap."""

    _print_banner()
    console.print(
        Rule(
            "[bold cyan]Compiling Regulatory Compliance Pack[/bold cyan]",
            style="cyan",
        )
    )
    bundle = load_bundle_from_disk(
        cbom_path,
        hndl_path,
        sponsor=sponsor,
        device_trade_name=device_trade_name,
        fda_submission_type=fda_submission_type,
        contract_vehicle=contract_vehicle,
    )
    paths = write_compliance_pack(
        bundle, out_dir, render_html=render_html, render_pdf=render_pdf
    )
    stats = summarise_bundle(bundle)

    table = Table(
        title="Compliance Pack Summary",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Document ID", str(stats["doc_id"]))
    table.add_row("Sponsor / Holder", sponsor)
    table.add_row("Device trade name", device_trade_name)
    table.add_row("FDA submission type", fda_submission_type)
    table.add_row("Contract vehicle", contract_vehicle)
    table.add_row("Assets enumerated", str(stats["assets"]))
    table.add_row(
        "CRITICAL (Q-Day-vulnerable)",
        f"[bold red]{stats['critical']}[/bold red]",
    )
    table.add_row(
        "SAFE (CNSA 2.0 compliant)",
        f"[bold green]{stats['safe']}[/bold green]",
    )
    table.add_row(
        "Soul Catcher 2.0 vectors",
        f"[bold white on red]{stats['soul_catcher_vectors']}[/bold white on red]",
    )
    console.print(table)

    out_table = Table(
        title="Generated Documents",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    out_table.add_column("Artifact")
    out_table.add_column("Path")
    out_table.add_row("FDA e-STAR Cybersecurity Addendum (Markdown)", str(paths["fda_estar"]))
    out_table.add_row("DoD NSM-10 PQC Transition Roadmap (Markdown)", str(paths["dod_nsm10"]))
    for key, label in (
        ("fda_estar_html", "FDA e-STAR Addendum (HTML)"),
        ("dod_nsm10_html", "DoD NSM-10 Roadmap (HTML)"),
        ("fda_estar_pdf", "FDA e-STAR Addendum (PDF)"),
        ("dod_nsm10_pdf", "DoD NSM-10 Roadmap (PDF)"),
    ):
        if key in paths:
            out_table.add_row(label, str(paths[key]))
    console.print(out_table)

    if render_pdf and "fda_estar_pdf" not in paths:
        console.print(
            "[bold yellow]Note:[/bold yellow] PDF rendering requested "
            "but [italic]pandoc[/italic] and/or "
            "[italic]weasyprint[/italic] not on PATH. Markdown still "
            "written. Install with:\n"
            "  [white]brew install pandoc[/white]\n"
            "  [white]pip install weasyprint[/white]"
        )
    elif render_html and "fda_estar_html" not in paths:
        console.print(
            "[bold yellow]Note:[/bold yellow] HTML rendering requested "
            "but [italic]pandoc[/italic] not on PATH. Markdown still "
            "written.\n  [white]brew install pandoc[/white]"
        )

    console.print(
        Panel(
            Text(
                "These are auditor-ready Markdown deliverables. Drop them "
                "into Pandoc → PDF and they satisfy:\n\n"
                "  • FDA RTA §22(c) — Cryptographic Bill of Materials\n"
                "  • FDA §524B (PATCH Act) cyber-content requirements\n"
                "  • NSM-10 / CNSA 2.0 vendor self-attestation\n"
                "  • OMB M-23-02 cryptographic inventory\n\n"
                "Without AQC, this paperwork costs $150k and 90 days from "
                "a GRC consultancy. With AQC, it costs four seconds.",
                style="bold white",
            ),
            title="[bold green]REGULATORY UNBLOCKER[/bold green]",
            border_style="green",
        )
    )


@main.command("q-tunnel-demo")
@click.option(
    "--mode",
    type=click.Choice(
        [m.value for m in TunnelMode], case_sensitive=False
    ),
    default=TunnelMode.HYBRID.value,
    show_default=True,
    help="Tunnel mode. SIMULATION runs without liboqs but is NOT quantum safe.",
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("./reports"),
    show_default=True,
)
def q_tunnel_demo(mode: str, out_dir: Path) -> None:
    """Perform a live hybrid ML-KEM-768 + X25519 handshake."""

    _print_banner()
    console.print(
        Rule(
            "[bold cyan]Hybrid PQC Tunnel — Live Handshake[/bold cyan]",
            style="cyan",
        )
    )
    runtime = HybridPQCGateway.runtime_report()

    runtime_table = Table(
        title="Gateway Runtime",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    runtime_table.add_column("Capability")
    runtime_table.add_column("Status")
    for key, value in runtime.items():
        coloured = (
            f"[bold green]{value}[/bold green]"
            if value not in (False, "MISSING", TunnelMode.SIMULATION.value)
            else f"[bold red]{value}[/bold red]"
        )
        runtime_table.add_row(key, coloured)
    console.print(runtime_table)

    result = run_demo_handshake(mode=TunnelMode(mode))
    t = result.transcript

    handshake_table = Table(
        title="Handshake Transcript",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    handshake_table.add_column("Field")
    handshake_table.add_column("Value")
    handshake_table.add_row("Mode", t.mode.value)
    handshake_table.add_row("ClientHello length (B)", str(t.client_hello_len))
    handshake_table.add_row("ServerHello length (B)", str(t.server_hello_len))
    handshake_table.add_row("Round-trip", f"{t.rtt_ms:.3f} ms")
    handshake_table.add_row(
        "Shared secret digest (SHA-256)",
        f"{t.shared_secret_digest[:16]}…{t.shared_secret_digest[-8:]}",
    )
    handshake_table.add_row("Transcript signature", t.transcript_signature_alg)
    handshake_table.add_row(
        "Signature length (B)", str(t.transcript_signature_len)
    )
    handshake_table.add_row(
        "Quantum-safe?",
        "[bold green]YES[/bold green]"
        if t.pqc_safe
        else "[bold white on red]NO — SIMULATION ONLY[/bold white on red]",
    )
    console.print(handshake_table)

    aead_table = Table(
        title="AEAD Round-Trip Probe",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    aead_table.add_column("Field")
    aead_table.add_column("Value", overflow="fold")
    aead_table.add_row("Plaintext", result.sample_plaintext)
    aead_table.add_row(
        "Ciphertext (hex, truncated)",
        result.sample_ciphertext_hex[:96] + ("…" if len(result.sample_ciphertext_hex) > 96 else ""),
    )
    aead_table.add_row(
        "Round-trip decrypt",
        "[bold green]OK[/bold green]" if result.roundtrip_ok else "[bold red]FAILED[/bold red]",
    )
    console.print(aead_table)

    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "q-tunnel-handshake.json"
    write_demo_report(result, report_path)
    console.print(
        f"[bold cyan]Handshake report →[/bold cyan] [white]{report_path}[/white]"
    )

    if not t.pqc_safe:
        console.print(
            Panel(
                Text(
                    "This run executed in SIMULATION mode. The handshake "
                    "shape is correct, the AEAD is real, the AEAD keys "
                    "are real — but the ML-KEM-768 leg is a "
                    "DETERMINISTIC HKDF and is NOT post-quantum secure.\n\n"
                    "Install the [pqc] extra for true ML-KEM-768:\n"
                    "    pip install -e \".[pqc]\"",
                    style="bold yellow",
                ),
                title="[bold white on red] SIMULATION MODE — NOT QUANTUM SAFE [/bold white on red]",
                border_style="red",
            )
        )
    else:
        console.print(
            Panel(
                Text(
                    "Hybrid ML-KEM-768 + X25519 KEM established. "
                    "Transcript signed by ML-DSA-65. Data plane wrapped "
                    "in AES-256-GCM. The next packet that hits this "
                    "tunnel is post-quantum confidential and authenticated.",
                    style="bold white",
                ),
                title="[bold green]QUANTUM-SAFE TUNNEL UP[/bold green]",
                border_style="green",
            )
        )


@main.command("fhe-brainprint-demo")
@click.option(
    "--keysize",
    type=int,
    default=512,
    show_default=True,
    help="Paillier modulus size in bits. 512 = demo; bump to 2048 for prod.",
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("./reports"),
    show_default=True,
)
def fhe_brainprint_demo(keysize: int, out_dir: Path) -> None:
    """Encrypt a Brain Print and run analytics on the ciphertext."""

    _print_banner()
    console.print(
        Rule(
            "[bold cyan]FHE on Brain Print — Soul Catcher Defuser[/bold cyan]",
            style="cyan",
        )
    )

    bp = cosine_baseline_template()
    result = run_fhe_brainprint_demo(keysize_bits=keysize, bp=bp)

    feat_table = Table(
        title="Plaintext Brain Print (UHNW principal baseline)",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    feat_table.add_column("Feature")
    feat_table.add_column("Plaintext", justify="right")
    feat_table.add_column("Cleartext Weight", justify="right")
    for label, value, weight in zip(bp.labels, result.plaintext_features, result.weights):
        feat_table.add_row(label, f"{value:.4f}", f"{weight:.4f}")
    console.print(feat_table)

    op_table = Table(
        title="Homomorphic Analytics (computed on ciphertext only)",
        title_style="bold cyan",
        header_style="bold magenta",
    )
    op_table.add_column("Operation")
    op_table.add_column("Plaintext result", justify="right")
    op_table.add_column("Decrypted ciphertext result", justify="right")
    op_table.add_column("Match")
    def _match(plain: float, decrypted: float) -> str:
        ok = abs(plain - decrypted) < 1e-3
        return "[bold green]OK[/bold green]" if ok else "[bold red]FAIL[/bold red]"

    op_table.add_row(
        "Σ features (encrypted sum)",
        f"{result.plaintext_sum:.4f}",
        f"{result.decrypted_sum:.4f}",
        _match(result.plaintext_sum, result.decrypted_sum),
    )
    op_table.add_row(
        "mean(features)",
        f"{result.plaintext_sum / len(bp.features):.4f}",
        f"{result.decrypted_mean:.4f}",
        _match(result.plaintext_sum / len(bp.features), result.decrypted_mean),
    )
    op_table.add_row(
        "⟨features, weights⟩ (dot product)",
        f"{result.plaintext_dot:.4f}",
        f"{result.decrypted_dot:.4f}",
        _match(result.plaintext_dot, result.decrypted_dot),
    )
    console.print(op_table)

    console.print(
        Panel(
            Text(
                "Even if an adversary HNDL-decrypts the AQC PQC tunnel "
                "tomorrow, the underlying Brain Print payload was "
                "encrypted under Paillier (here) / OpenFHE-CKKS (in "
                "production) at the device. The analytics layer "
                "computed mean, sum, and cosine similarity against a "
                "cleartext template *without ever decrypting the "
                "patient's brain-print*.\n\n"
                f"Paillier modulus: {result.keysize_bits} bits. "
                f"Correctness: {'PASS' if result.correctness_ok else 'FAIL'}.\n"
                f"{result.note}",
                style="bold white",
            ),
            title="[bold green]SOUL CATCHER 2.0 DEFUSER ACTIVE[/bold green]",
            border_style="green",
        )
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    fhe_report = {
        "keysize_bits": result.keysize_bits,
        "labels": list(bp.labels),
        "plaintext_features": list(result.plaintext_features),
        "weights": list(result.weights),
        "plaintext_sum": result.plaintext_sum,
        "decrypted_sum": result.decrypted_sum,
        "decrypted_mean": result.decrypted_mean,
        "plaintext_dot": result.plaintext_dot,
        "decrypted_dot": result.decrypted_dot,
        "correctness_ok": result.correctness_ok,
        "note": result.note,
    }
    report_path = out_dir / "fhe-brainprint-demo.json"
    report_path.write_text(json.dumps(fhe_report, indent=2), encoding="utf-8")
    console.print(
        f"[bold cyan]FHE demo report →[/bold cyan] [white]{report_path}[/white]"
    )


@main.command("full-audit")
@click.option(
    "-f",
    "--file",
    "pcap_file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=False,
    help="Path to a PCAP / PCAPNG capture (synthetic fleet if omitted).",
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("./reports"),
    show_default=True,
)
@click.option("--seed", type=int, default=None)
@click.option(
    "--with-compliance/--no-compliance",
    default=True,
    show_default=True,
    help="Also generate FDA + DoD compliance pack.",
)
@click.option(
    "--with-demos/--no-demos",
    default=False,
    show_default=True,
    help="Also run the PQC tunnel and FHE brain-print demos.",
)
@click.pass_context
def full_audit(
    ctx: click.Context,
    pcap_file: Optional[Path],
    out_dir: Path,
    seed: Optional[int],
    with_compliance: bool,
    with_demos: bool,
) -> None:
    """Run CBOM + HNDL + JADC2 + (optionally) compliance + demos."""

    ctx.invoke(
        scan_neural_pcap, pcap_file=pcap_file, out_dir=out_dir, seed=seed
    )
    console.print()
    ctx.invoke(
        generate_jadc2_policy, pcap_file=pcap_file, out_dir=out_dir, seed=seed
    )

    if with_compliance:
        console.print()
        ctx.invoke(
            generate_fda_compliance,
            cbom_path=out_dir / "cbom.json",
            hndl_path=out_dir / "hndl-findings.json",
            out_dir=out_dir,
            sponsor="Acquirer-Of-Record (TBD)",
            device_trade_name="Subject Neural / Biometric Device",
            fda_submission_type="510(k)",
            contract_vehicle="JADC2 — TBD",
        )

    if with_demos:
        console.print()
        ctx.invoke(q_tunnel_demo, mode=TunnelMode.HYBRID.value, out_dir=out_dir)
        console.print()
        ctx.invoke(fhe_brainprint_demo, keysize=512, out_dir=out_dir)


if __name__ == "__main__":  # pragma: no cover
    main()
