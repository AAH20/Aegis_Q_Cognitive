# Aegis Quantum-Cognitive (AQC)

Open-source **PQC readiness auditor** for neural, biometric, and **JADC2** traffic.

It ingests PCAP captures (or a synthetic neural fleet), builds a **CycloneDX CBOM**, runs an **HNDL / Soul Catcher** audit on data in transit, and emits a **Quantum-Resistant Identity-First Segmentation** policy (YAML).

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Python **3.11+** required.

## Usage

```bash
aqc scan-neural-pcap -f capture.pcap -o ./reports
aqc generate-jadc2-policy -o ./reports
aqc full-audit -o ./reports
```

## License

Apache-2.0.
