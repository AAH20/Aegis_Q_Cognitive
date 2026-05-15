# Aegis Quantum-Cognitive — Capital Formation Brief (May 2026)

This document is a **strategic narrative and execution outline** for raising capital around AQC-class offerings (compliance automation, PQC readiness, and simulated continuous-assurance demos). It is **not** legal, securities, tax, or export-control advice. Run investor outreach, syndicate structure, and product claims past qualified counsel before sending materials or offering allocations.

---

## Positioning: threat briefings, not generic SaaS pitches

Dual-use and defense-adjacent capital often responds to **compressed technical proof** plus **regulatory urgency** more than to classic TAM slides. The goal is to show **why the market must move now** (RTA-shaped cyber expectations, NSM-10 / CNSA transition pressure, HNDL on long-lived biometrics) and **what your system generates in minutes** that incumbents bill in quarters.

Keep every live demo **strictly aligned with repository behavior**: CBOM and HNDL analysis on PCAP or synthetic fleets; FDA / DoD compliance artifacts from `compliance_compiler`; hybrid tunnel demo from `q_tunnel_gateway` (real PQC when `liboqs` is available, otherwise clearly labeled simulation); FHE brain-print **property demo** via Paillier; **Interrogation AGI** as a **simulated** Gymnasium environment plus tabular RL and Rich War Room UI — **not** live exploitation of third-party networks, **not** a claim to “break AES-GCM” in production systems.

---

## Phase 1 — Angels and family offices (seed)

**Typical profile:** UHNW individuals, single-family offices, founder-angels with personal exposure to wearables, metabolic tech, or experimental BCIs.

**Psychology:** Allocate when the risk is **legible** (their own attack surface, or their principals’) and the mitigation is **concrete** (inventory, roadmap, wrap architecture).

**Illustrative terms (example only):** on the order of **$1.5M–$3M** on **~$15M pre-money** — always subject to counsel, market, and instrument choice (SAFE vs priced equity).

**Execution:**

1. **Hook — scoped, consented context.** Prefer **device class** and **public standards** over non-consensual “surveillance theater.” Offer a **signed scoping** or use **synthetic / public paralle**l data. Personalization (“your exact ring”) requires explicit permission and a clear data-handling story.
2. **Demo:** `aqc full-audit` (and, where relevant, compliance generation from resulting `cbom.json`) to show **repeatable** outputs — CBOM, HNDL findings, JADC2-oriented policy, optional tunnel and FHE demos.
3. **Narr thread:** Long-lived **biometric and neural telemetry** is a high-value HNDL target; classical asymmetric protection may not age well; **inventory + transition roadmap + cryptographic controls** are the defensible response *before* Q-day discussions become operational crises.
4. **Close:** Tie **allocation** to **deployed outcomes** (audit methodology, retainer shape, gateway / segmentation deliverables) — not to fear alone. Document what investors receive **in kind** vs as securities.

---

## Phase 2 — Deep tech and dual-use venture (Series A scale)

**Typical profile:** Funds with American dynamism, national security, or hard-tech theses; partners who understand **program revenue**, **compliance moats**, and **long sales cycles**.

**Psychology:** They need **venture-scale outcomes** — recurring revenue, expansion within accounts, and a story that survives technical diligence.

**Illustrative terms (example only):** **$10M–$15M** on **$50M+** post-seed pricing — highly market-dependent.

**Execution:**

1. **Hook — procurement and regulatory friction.** FDA cyber/refusal risk and DoD PQC migration pressure create **mandatory spend** categories; the question is who automates the **critical path artifacts** with audit-friendly provenance.
2. **Demo:** Walk `compliance_compiler` inputs/outputs: from CBOM (+ optional HNDL JSON) to **FDA e-STAR–shaped addendum** and **NSM-10–style roadmap** markdown — emphasize **time-to-draft** and **repeatability**, not “300 pages in four seconds” unless you can **show** page count and version hash on screen.
3. **Narr thread:** Position as **compliance and crypto-inventory automation** that sits **upstream** of pen tests and **downstream** of engineering truth (build-linked CBOM).
4. **Close:** Syndicate story (e.g. US operator / advisor relationships) belongs in **contracts and bios**, not slogans. Be precise about **roles**, **compensation**, **cleared work**, and **conflicts**.

---

## Phase 3 — Defense and GovTech private equity (growth)

**Typical profile:** PE firms that underwrite **sticky government-facing revenue**, **cleared delivery**, and **bolt-on** value for primes.

**Psychology:** They buy **cash-flow durability**, **account penetration**, and **defensible IP / workflow**, not slide decks.

**Illustrative ask (example only):** **$30M+** strategic growth equity — structure and control terms are deal-specific.

**Execution:**

1. **Hook — continuous assurance in owned environments.** “Annual pentest” narratives are weak for operators; **persistent red-team **and** training harnesses** in **authorized ranges** are strong — if you separate **production security testing** from **R&D simulation** clearly.
2. **Demo:** `aqc unleash-interrogator --epochs …` after `pip install -e ".[agi]"` — full-screen **War Room**; **simulated** gateway integrity, rewards, Soul Catcher–flavored **narrative log**. State explicitly: **no raw Internet attacks**, **no spoofing of real BCIs**, **RL env is a model for executive and range education**.
3. **Narr thread:** **Sentinel-tier** story = **air-gapped or controlled deployment**, **sovereign red-team**, **FMS / ally modernization** angles only with **export and program facts** vetted by counsel.
4. **Geopolitical lever:** MENA, F-16 ecosystems, or sovereign facilities must be described with **accurate program mechanics** and **compliance**; avoid speculative claims that diligence cannot verify.

---

## 30-day execution roadmap (template)

| Week | Focus | Actions |
| ---- | ----- | ------- |
| **1** | **Teaser discipline** | Short **threat + standards** memo (HNDL, RTA cyber expectations, CNSA timeline); anonymized or synthetic CBOM excerpt; **no** unsolicited security claims about named portfolio companies without legal review. |
| **2** | **Syndicate paperwork** | Advisor / JV terms executed or at term-sheet; **team slide** matches **contracts** and **bios**. |
| **3** | **Regional roadshow** | MENA / Gulf meetings with **export** and **sanctions** posture documented; materials reviewed for **localization** and **accuracy**. |
| **4** | **Process compression** | If a credible anchor commits, **update US process** with **specific milestones** (not vague FOMO). Maintain **one data room** with: sample outputs, architecture diagram, simulation disclaimers for AGI module, and security whitepaper if available. |

---

## Investor data room — suggested artifacts

- `cbom.json` sample (synthetic or redacted).
- `hndl-findings.json` sample and interpretation one-pager.
- `jadc2-segmentation.yaml` excerpt.
- FDA / NSM-10 markdown outputs from `generate-fda-compliance` (redacted sponsor strings if needed).
- Screenshots or recordings of `q_tunnel-demo` and `fhe-brainprint-demo` with **mode labels** (PQC vs simulation).
- **Interrogation AGI:** architecture one-pager stating **Gymnasium + Q-learning + simulated gateway**; link to `src/aqc/agi_interrogator/README` or source tree; **no** equivalence to live zero-day sales without evidence.

---

## Risk and compliance checklist (non-exhaustive)

- **Securities:** Marketing vs general solicitation; accredited investor rules; forward-looking statements; any **allocation** language reviewed by counsel.
- **Export:** ITAR/EAR classification of **source**, **services**, and **deployment**; country screens for roadshows.
- **Privacy / cyber:** Consent for demos involving personal devices; safe handling of any captured data.
- **Technical marketing:** Every bullet in a deck should map to **a command**, **a file**, or **a documented limitation** in this repository or your commercial product line.

---

## One-line internal mantra

**Allocate equity in a monopoly only after the monopoly is defined as: measurable artifacts, repeatable demos, signed customer or program traction, and counsel-approved claims.**
