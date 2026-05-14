# Aegis Quantum-Cognitive (AQC)

Open-source **PQC readiness auditor** for neural, biometric, and **JADC2** traffic — plus **auditor-ready FDA / DoD compliance** generation from a CBOM.

## Capabilities

- **CBOM** (CycloneDX 1.6) + **HNDL / Soul Catcher** audit.
- **JADC2** quantum-safe microsegmentation policy (YAML).
- **FDA e-STAR Cybersecurity Addendum** + **DoD NSM-10 PQC Transition Roadmap** (Markdown) via `aqc generate-fda-compliance`.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
aqc scan-neural-pcap -o ./reports
aqc generate-jadc2-policy -o ./reports
aqc generate-fda-compliance --cbom ./reports/cbom.json --hndl ./reports/hndl-findings.json -o ./reports
aqc full-audit -o ./reports   # runs scan + policy + compliance pack
```

Optional: `brew install pandoc` and `pip install -e ".[render]"` for HTML/PDF export.

## License

Apache-2.0.
