# STS — Sovereign Task System

A hybrid workspace combining a **React dashboard front-end** with a **Python
sovereign-engine / benchmark back-end** for edge-device (Jetson AGX Orin)
chaos testing, hash-chained sealed ledgers, and tamper-evident checkpoint
anchoring.

## Repository Layout

```
.
├── src/                    # Front-end + sovereign engine
│   ├── App.tsx             # React dashboard (Vite + Tailwind CSS v4)
│   ├── components/         # TaskBoard, StatsPanel, ActivityFeed, QuickActions
│   └── sovereign_engine/   # Core policy engine (single importable namespace)
│       ├── engine/         #   quarantine, recovery, transition gate
│       ├── execution/      #   execution boundary
│       ├── gate/           #   predicates, STS clock
│       └── types/          #   authorization, evidence, transitions
├── bench/                  # Chaos benchmark & anchoring stack
│   ├── main.py             # STS Core Command anchor server (FastAPI)
│   ├── pipeline.py         # Benchmark pipeline (telemetry + faults + ledger)
│   ├── run_benchmark.py    # Stable CLI alias for the pipeline
│   ├── ledger.py           # SEALedger: append-only, hash-chained JSONL ledger
│   ├── anchor.py           # Merkle checkpoint anchoring over ledger events
│   ├── core_db.py          # WORM (write-once-read-many) SQLite anchor store
│   └── hardware_hooks.py   # Device-side fault hooks
├── tests/                  # pytest suite (unit, sovereign, abide, harness)
├── chaos_hooks.py          # Exception-safe chaos hooks (tegrastats, netem, stress-ng)
├── docs/reports/           # Generated provenance / benchmark reports
└── index.html              # Vite entry point
```

## Prerequisites

- Node.js 18+ and npm
- Python 3.10+ with `pip`
- For the full chaos benchmark on real hardware: an NVIDIA Jetson AGX Orin
  (or generic Linux) with `tegrastats`, `tc` (netem), and `stress-ng`
  installed, plus root privileges for qdisc injection.

## Front-end (React + Vite)

```bash
npm install --include=dev     # installs deps AND devDependencies (tailwind, vite, tsc)
npm run dev                   # dev server on port 3000 (host 0.0.0.0)
npm run build                 # production build
npm run typecheck             # tsc --noEmit
```

Stack: React 18, TypeScript, Vite 6, Tailwind CSS v4 (`@tailwindcss/vite`),
framer-motion, lucide-react, recharts, @dnd-kit, date-fns, uuid, Supabase JS.

> Note: `npm ci` requires `package-lock.json` to be in sync with
> `package.json`. If you hit an `EUSAGE` error, regenerate the lockfile with
> `npm install` before retrying.

## Back-end & Benchmark (Python)

Run everything from the **repo root** so `pythonpath = . src` (see
`pytest.ini`) resolves `sovereign_engine`, `bench.*`, and `tests.*` correctly.

### Core Command anchor server

```bash
uvicorn bench.main:app --host 0.0.0.0 --port 8000
```

The server accepts batched checkpoint anchors from edge nodes at
`POST /anchors/batch`, validating Ed25519 device keys, sequence continuity,
and hash-chain linkage before committing into the WORM store
(`bench/core_db.py`), which enforces immutability via SQLite
`BEFORE UPDATE` / `BEFORE DELETE` triggers.

### Chaos benchmark pipeline

```bash
STS_LEDGER_KEY=<hex-or-passphrase> python3 -m bench.run_benchmark \
    --phases baseline stress verification --interface eth0
```

Each phase appends a hash-chained, HMAC-sealed row to
`data/reports/ledger.jsonl`; the run is audited and sealed with a
`.seal.json` manifest, and `results.json` embeds the audit report so
provenance can be verified offline via `SEALedger.verify_seal()`.

Chaos injection itself is driven by `chaos_hooks.py`, whose context managers
are exception-safe — cleanup always runs, so a failed test can never leave
the device degraded:

- `TegrastatsMonitor` — background CSV telemetry capture (`tegrastats --interval 500`)
- `network_degradation` — `tc`/netem qdisc injection with guaranteed teardown
- `hardware_saturation` — `stress-ng` CPU/VM/IO load with guaranteed termination

### Tests

```bash
python3 -m pytest            # whole suite; pythonpath handles namespace resolution
python3 -m pytest tests/unit # e.g. evidence-type contracts
```

`pytest.ini` excludes `mutants/`, `.hypothesis/`, and `node_modules/` from
collection and disables the incompatible bundled `libtmux` plugin
(`-p no:libtmux`).

## CI / Provenance

`.github/workflows/generator-generic-ossf-slsa3-publish.yml` generates SLSA
level-3 build provenance on release via the OpenSSF
`slsa-github-generator`. Verify artifacts with
[`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier).

Sample provenance records live in `docs/reports/`.

## Security Model Summary

| Layer | Mechanism |
|---|---|
| Ledger integrity | SHA-256 hash chain per line; structural tampering detectable without the key |
| Provenance | Per-row HMAC-SHA256 (`SEALedger`), verifiable/re-sealable with `STS_LEDGER_KEY` |
| Anchor store | WORM SQLite table with update/delete triggers, WAL mode, idempotent batch commits |
| Device identity | Ed25519 keys registered per device; malformed keys rejected at registration |
| Build provenance | SLSA L3 via GitHub Actions generic generator |

## License

See [LICENSE](LICENSE).
