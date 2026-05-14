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
@click.pass_context
def full_audit(
    ctx: click.Context,
    pcap_file: Optional[Path],
    out_dir: Path,
    seed: Optional[int],
) -> None:
    """Run CBOM + HNDL + JADC2 segmentation pipeline."""

    ctx.invoke(
        scan_neural_pcap, pcap_file=pcap_file, out_dir=out_dir, seed=seed
    )
    console.print()
    ctx.invoke(
        generate_jadc2_policy, pcap_file=pcap_file, out_dir=out_dir, seed=seed
    )


if __name__ == "__main__":  # pragma: no cover
    main()
