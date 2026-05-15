"""CI/CD static gate: classical asymmetric usage in bio-telemetry surfaces.

Intended for MedTech / wearable repos that wire **biometric or neural**
code paths with **TLS / legacy asymmetric** primitives. This is a
**heuristic** lead-in to fuller CBOM + AKB review — not a substitute for
formal FDA validation or a full crypto audit.

Exit code ``1`` only when:

* A file is in *biometric / telemetry / BCI context* (path or content), **and**
* The file (or a co-scoped snippet) shows **classical asymmetric** imports
  or explicit ``ssl`` client usage, **and**
* No **PQC / hybrid** hint (``oqs``, ``ML-KEM``, ``mlkem``, etc.) appears in
  that file.

Downstream teams can set ``AQC_CI_REMEDIATION_CONTACT`` for the CTA footer.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Path segments suggesting bio / RF / clinical transport context.
_BIO_PATH_RE = re.compile(
    r"(bci|eeg|ble|bluetooth|biometric|neural|telemetry|wearable|"
    r"medical|patient|glucose|pacemaker|oura|whoop|soul_catcher|hndl|"
    r"jadc2|implant|headband|cgm|nih|fda|510k)",
    re.IGNORECASE,
)

# File content must also lean "transport / device" if path is weak.
_BIO_CONTENT_RE = re.compile(
    r"(bci|eeg|ble\b|bluetooth|biometric|neuralink|wearable|telemetry|"
    r"pacemaker|glucose|patient|medical device|heart rate|spo2|hndl)",
    re.IGNORECASE,
)

# Import / API patterns = classical asymmetric or legacy TLS client.
_CLASSICAL_CODE_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "cryptography asymmetric RSA",
        re.compile(
            r"(cryptography\.hazmat\.primitives\.asymmetric\.rsa\b|"
            r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+[^\n#]*\brsa\b)"
        ),
    ),
    (
        "cryptography EC module",
        re.compile(r"cryptography\.hazmat\.primitives\.asymmetric\.ec\b"),
    ),
    (
        "X25519 / X448 (classical ECDH-class)",
        re.compile(
            r"cryptography\.hazmat\.primitives\.asymmetric\.(x25519|x448)\b"
        ),
    ),
    ("ecdsa package", re.compile(r"^\s*(from|import)\s+ecdsa\b")),
    (
        "ssl client wrappers",
        re.compile(
            r"\b(ssl\.(create_default_context|SSLContext)|"
            r"ssl\.wrap_socket)\b"
        ),
    ),
)

_PQC_HINT_RE = re.compile(
    r"\b("
    r"liboqs|oqs\.|import\s+oqs|"
    r"fips\s*203|fips\s*204|"
    r"ml[\s_-]?kem|MLKEM|kyber|dilithium|ml[\s_-]?dsa|"
    r"sphincs|falcon|slh[\s_-]?dsa|hybrid.*kem|"
    r"pqc|PQC_|"
    r"aqc:ci-allow-classical"  # explicit escape hatch for hybrid demos
    r")\b",
    re.IGNORECASE,
)

_CI_IGNORE_LINE = re.compile(r"aqc:\s*ci-ignore-line")

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".github",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".eggs",
        ".pytest_cache",
        ".tox",
        "htmlcov",
    }
)

console = Console(stderr=True, highlight=False)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _is_biometric_context(rel_posix: str, text: str) -> bool:
    if _BIO_PATH_RE.search(rel_posix.replace("\\", "/")):
        return True
    return bool(_BIO_CONTENT_RE.search(text))


def _classical_hits(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _CI_IGNORE_LINE.search(line):
            continue
        if line.lstrip().startswith("#"):
            continue
        for label, pattern in _CLASSICAL_CODE_RES:
            if pattern.search(line):
                hits.append((label, f"{line_no}:{line.strip()[:120]}"))
    return hits


def _has_pqc_hint(text: str) -> bool:
    return bool(_PQC_HINT_RE.search(text))


def audit_repo(
    root: Path,
    *,
    exclude_prefixes: list[str],
    extensions: frozenset[str],
) -> list[dict[str, object]]:
    """Return list of violation dicts."""

    violations: list[dict[str, object]] = []
    root = root.resolve()

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(rel.startswith(p) or f"/{p}" in f"/{rel}/" for p in exclude_prefixes):
            continue
        parts = set(path.parts)
        if parts & _SKIP_DIRS:
            continue
        if path.suffix.lower() not in extensions:
            continue

        text = _read_text(path)
        if not text.strip():
            continue
        if not _is_biometric_context(rel, text):
            continue
        hits = _classical_hits(text)
        if not hits:
            continue
        if _has_pqc_hint(text):
            continue
        violations.append(
            {
                "path": rel,
                "hits": hits,
            }
        )
    return violations


def _print_pass(root: Path, scanned_note: str) -> None:
    console.print(
        Panel.fit(
            Text(
                "PQC CI gate: no HNDL-classical asymmetric surface detected\n"
                f"in biometric/telemetry-scoped modules under {root}.",
                style="green",
            ),
            title="[bold green]AQC CI AUDIT — PASS[/bold green]",
            border_style="green",
        )
    )
    console.print(Text(scanned_note, style="dim"))


def _print_fail(violations: list[dict[str, object]], contact: str) -> None:
    console.print(Rule(style="red bold"))
    title = Text("CRITICAL FDA RTA / NSM-10 SURFACE (CI GATE)", style="bold white on red")
    console.print(Panel(title, style="red"))
    body = Text(
        "HNDL-vulnerable classical asymmetric or legacy TLS patterns were "
        "detected in source that matches bio / neural / telemetry context.",
        style="white",
    )
    body.append(
        "\n\nBuild halted per AQC CI policy (heuristic MedTech transport gate).\n",
        style="yellow",
    )
    console.print(Panel(body, border_style="red"))
    table = Table(title="Violations", header_style="bold red", expand=True)
    table.add_column("File")
    table.add_column("Pattern")
    table.add_column("Location")
    for v in violations:
        p = str(v["path"])
        for label, loc in v["hits"]:  # type: ignore[assignment]
            table.add_row(p, label, loc)
    console.print(table)
    cta = Text()
    cta.append(
        "\nTo unblock: migrate key establishment to ML-KEM-768 (hybrid) and "
        "authentication to ML-DSA-65 where appropriate; reference NSA CNSA 2.0 "
        "and FDA premarket cybersecurity expectations.\n\n",
        style="white",
    )
    cta.append("Emergency PQC remediation, CBOM, and FDA e-STAR support: ", style="bold yellow")
    cta.append(contact, style="bold cyan underline")
    cta.append("\n", style="white")
    console.print(Panel(cta, title="[bold]Next step[/bold]", border_style="yellow"))
    console.print(Rule(style="red bold"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AQC MedTech-oriented PQC CI static gate (heuristic).",
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        type=Path,
        help="Repository root to scan (default: cwd).",
    )
    parser.add_argument(
        "--extensions",
        default=os.environ.get("AQC_CI_EXTENSIONS", ".py"),
        help="Comma-separated file extensions (default: .py).",
    )
    args = parser.parse_args(argv)

    root = args.root
    ext_set = frozenset(
        e.strip().lower() if e.strip().startswith(".") else f".{e.strip().lower()}"
        for e in args.extensions.split(",")
        if e.strip()
    ) or frozenset({".py"})

    raw_excl = os.environ.get("AQC_CI_EXCLUDE_PREFIXES", "")
    exclude_prefixes = [
        x.strip().rstrip("/") for x in raw_excl.split(",") if x.strip()
    ]
    # Sensible defaults when env not set (consumer repos usually omit this).
    if not exclude_prefixes:
        exclude_prefixes = []

    contact = (
        os.environ.get("AQC_CI_REMEDIATION_CONTACT", "").strip()
        or "ops@aegis-quantum-cognitive.example"
    )

    violations = audit_repo(root, exclude_prefixes=exclude_prefixes, extensions=ext_set)
    note = (
        f"Extensions: {', '.join(sorted(ext_set))}. "
        "Excludes: " + (", ".join(exclude_prefixes) or "(none)") + "."
    )

    if violations:
        _print_fail(violations, contact)
        return 1

    _print_pass(root.resolve(), note)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
