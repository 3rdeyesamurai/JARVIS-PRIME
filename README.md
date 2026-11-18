# JARVIS PRIME

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D4.svg)](#requirements)


JARVIS PRIME is a Windows-focused defensive security suite that combines
network and Windows event monitoring, automatic firewall containment, local
semantic retrieval of protective scripts, a real-time process/I/O dashboard,
and an autoresearch loop for improving security and performance behavior.

This README is a Graphify-assisted inventory of the project as it exists in
this snapshot. Graphify's unified graph reports **242 nodes, 327 edges, and
20 communities**. The graph also includes the referenced `autoresearch`
checkout outside this folder; that component is documented below as an
external dependency rather than as a file guaranteed to be present here.

> **Important:** This is active defensive software. Several scripts change
> Windows Firewall rules, stop services, create scheduled tasks, and execute
> generated PowerShell/Python. Test in a disposable environment first and
> review generated responses before enabling live mode.

## Feature catalog

### Defensive monitoring

- **Windows Firewall containment**: baselines external listener bindings,
  detects newly exposed ports, blocks unexpected inbound listeners, locks Ollama
  to loopback, and can block public attacker IPs.
- **Windows Security event monitoring**: detects failed logons, new accounts,
  administrator-group changes, new services, and suspicious outbound activity.
- **Network threat analysis**: analyzes `netstat` connections, privileged/
  registered/ephemeral port entropy, and Rule-30 cellular-automaton chaos.
- **Forensic snapshots**: collects connections, users, processes, and recent
  Windows Security events for incident review.
- **Real-time service tracking**: starts or stops Windows Search through
  Search Guardian and reports service transitions.

### Intelligence and response

- **Semantic mitigation retrieval**: uses ChromaDB and
  `all-MiniLM-L6-v2` embeddings to find protective scripts.
- **Threat classification**: identifies brute force, privilege escalation,
  new service, exposed port, suspicious outbound, high-entropy, and unknown threats.
- **Rule-30 response scramble**: varies candidate selection using a
  persistent hash/salt.
- **Novel-threat research**: generates and indexes a typed mitigation script
  when a semantic match exceeds the novelty threshold.
- **Safety policy**: defaults to review/dry-run mode; live execution requires
  an explicit `approved_live` policy and appropriate Windows permissions.
- **Stale-path recovery**: remaps old response-script locations into the
  active bundled response directory and converts misclassified Bash/PowerShell
  responses to the correct executable format.
- **Persistent state**: tracks byte offsets, seen threat hashes, amendment
  counters, response counters, and response history.

### Security dashboard

- **Loopback-only web UI**: runs locally at `http://127.0.0.1:8765`.
- **Bearer-token protection**: API and SSE requests require the token stored in
  `runtime\dashboard-token`.
- **Live Server-Sent Events**: streams process snapshots and kernel I/O events.
- **Kernel I/O view**: live process read/write bytes, rates, derivation labels,
  open-file hints, flags, and security events.
- **Process table**: CPU, memory, threads, network connections, I/O totals,
  component classification, and sortable process columns.
- **RAG port status**: exposed listeners are labeled Red/Amber/Green:
  - **Green** — matched to the known-safe baseline.
  - **Amber** — open but not matched and needs review.
  - **Red** — newly exposed, manipulated, or an unexpected shell/interpreter
    may be exposing the port.
- **Plain-language port explanations**: explains what is open, blocked,
  stopped, matched, or suspicious for non-technical users.
- **Port dropdown controls**: block an inbound port, block and stop the
  owning process, or restore/unblock the port.
- **Browser and Windows notifications**: alerts on new Red port signatures
  without repeatedly notifying for the same unchanged state.
- **Firewall rule view**: lists active JARVIS `WF-*` firewall rules.
- **Alert log view**: streams recent intrusion and response log entries.
- **Analytics dashboard**: disk reads/writes, network rates, CPU share,
  kernel/user activity, component I/O, and five-minute/one-hour/24-hour windows.
- **Memory database**: security-event and metric history with retention controls.
- **Transmission pipeline**: reports collection, queue fan-out, SSE delivery,
  subscriber, byte, tick, and disconnect counters.
- **Process allow-list**: discovers processes and saves approved names for
  outbound-throttle behavior.
- **Graph hypotheses**: displays cached Graphify hypotheses and graph metrics.
- **Autoresearch metrics**: security score, violation/refusal rates, scramble
  diversity, performance findings, and research iteration history.

### Dashboard controls

The Overview tab can launch or schedule:

- Quantum scan
- Scramble tuning
- Web-Fortress setup, monitoring, and scheduled auto-block mode
- Intruder-Protocol installation and monitoring
- Windows hardening
- JARVIS PRIME one-shot or daemon mode
- Autoresearch one-shot or daemon mode
- Search Guardian
- Outbound throttle dry-run or live mode

### Outbound throttle

- Rule-30-derived throttle levels and compression settings.
- Live process/upload status table.
- 30-minute browser-grace behavior.
- Allow-list-based exception handling.
- Dry-run mode for safe review before live throttling.

### Desktop controller

- Tkinter Windows control window for running JARVIS in least-privilege mode.
- Starts the loopback dashboard, JARVIS loop, Search Guardian, Quantum
  Analyzer, and optional PowerShell watchers.
- Enforces review/dry-run by default.
- Per-user Startup-folder installation without an administrator scheduled task.
- Packaged with PyInstaller under `dist\JarvisPrime\`.

## What is implemented

### Detection and containment

- **Web-Fortress** (`web-fortress.ps1`)
  - Baselines external listening ports and process bindings.
  - Detects new external listeners by diffing against the baseline.
  - Blocks unexpected inbound ports with Windows Firewall rules.
  - Locks Ollama to `127.0.0.1` and blocks external access to port `11434`.
  - Detects unusual outbound connections.
  - Blocks public attacker IPs after repeated Windows Security event `4625`
    failures or critical alert-log findings.
  - Supports one-shot, continuous-watch, status, and scheduled-task modes.

- **Intruder Protocol** (`intruder-protocol.ps1`)
  - Detects brute force activity from event `4625`.
  - Detects new accounts and privilege-group changes (`4720`, `4728`, `4732`).
  - Detects newly installed services (`7045`).
  - Flags unusual outbound connections.
  - Captures forensic snapshots containing connections, users, processes, and
    recent Security events.
  - Emits console, file, and best-effort Windows toast alerts.
  - Can install a SYSTEM scheduled task that runs every two minutes.

- **Quantum Analyzer** (`quantum-analyzer.py`)
  - Reads `netstat -ano` connection state.
  - Computes Shannon entropy over privileged, registered, and ephemeral port
    bands.
  - Computes Rule-30 cellular-automaton chaos density from port presence.
  - Produces a quantized `0-10` threat score:
    - `0-3`: `NOMINAL`
    - `4-6`: `ELEVATED`
    - `7-10`: `CRITICAL`
  - Enriches suspicious remote endpoints with local `nslookup` output.
  - Writes `quantum-report.json` and triggers JARVIS PRIME for scores `>= 4`.

### Intelligence-to-response bridge

- **JARVIS PRIME engine** (`jarvis_prime.py`)
  - Tails `intruder-alerts.log` incrementally using a persisted byte offset.
  - Deduplicates previously handled alerts with bounded hashes.
  - Classifies threats into brute force, new admin, new service, port exposure,
    suspicious outbound, high entropy, or unknown.
  - Queries the local ChromaDB collection using the
    `all-MiniLM-L6-v2` embedding model.
  - Uses a Rule-30 scramble seeded by a salted hash to vary candidate
    selection.
  - Treats a vector distance above `0.80` as a novel threat.
  - Generates a new mitigation script for novel threats, stores it in
    `jarvis-responses/`, and amends the vector database.
  - Executes known or newly generated responses.
  - Supports daemon mode, one-shot processing, and dry-run planning.
  - Persists amendment and response counters in `jarvis-state.json`.

- **Response templates**
  - Brute-force IP blocking and audit-policy adjustment.
  - Administrator membership auditing and forensic snapshotting.
  - Suspicious-service stopping and disabling.
  - External listener containment.
  - Suspicious outbound-port blocking.
  - High-entropy lockdown and emergency inbound blocking.

### Local protective-script knowledge base

- **Vector DB bridge** (`vector-db/cybersec_protective_scripts_vector_db.py`)
  - Persistent ChromaDB collection: `protective_scripts_v1`.
  - CPU-friendly local embedding model: `all-MiniLM-L6-v2`.
  - Semantic search with optional asset-category filtering.
  - Add custom protective scripts.
  - Ordered asset taxonomy covering:
    - hardware and endpoints
    - software and operating systems
    - data, logs, backups, and secrets
    - networks, APIs, DNS, and PKI
    - identities, privileged access, and RBAC
    - cloud, virtual, hybrid, and serverless assets
    - facilities and supporting infrastructure
    - third-party and supply-chain assets
  - Includes Windows hardening, Linux server hardening, identity auditing,
    backup encryption, network monitoring, and maintenance examples.

### Dashboard and observability

- **Security Dashboard** (`security-dashboard.py`)
  - Local web UI at `http://localhost:8765`.
  - Real-time Server-Sent Events stream at `/api/stream`.
  - One-second phase-locked `psutil` kernel/process monitor.
  - Process CPU, memory, threads, network connections, read/write rates, and
    derived I/O labels.
  - Active-process and security-flag event stream.
  - Firewall rule view, alert view, threat report, and stasis/research state.
  - SQLite analytics database with 24-hour I/O retention.
  - SQLite memory database with seven-day security-event and 30-day metric
    retention.
  - Pipeline instrumentation for collection, queue fan-out, SSE delivery, and
    browser consumption.
  - Dashboard controls to launch configured tools as background jobs.
  - Allow-list read/write endpoints and process discovery for the UI.
  - Graph-hypothesis endpoint backed by the local Graphify integration when
    available.

### Search and lifecycle helpers

- **Search Guardian** (`search_guardian.py`)
  - Starts Windows Search when search processes appear.
  - Stops `WSearch` after 90 seconds of inactivity.
  - Polls every three seconds and logs transitions.

- **Unified launcher** (`jarvis-prime-launcher.ps1`)
  - Starts Web-Fortress, Intruder Protocol, Dashboard, Search Guardian,
    Quantum Analyzer, JARVIS PRIME, and the external autoresearch loop.
  - Supports `-Silent`, `-Install`, and `-Stop`.
  - Tracks child PIDs and provides a fallback process-name shutdown path.

- **Self-elevating launcher** (`jarvis-prime-start.bat`)
  - Requests Administrator privileges and invokes the PowerShell launcher.

### Autoresearch and optimization integration

The Graphify graph identifies an external `AndroidStudioProjects\autoresearch`
component containing:

- `security_research_loop.py`: keep/revert recursive experimentation loop.
- `violation_tracker.py`: parses logs and computes security metrics.
- `perf_researcher.py`: snapshots resource use and recommends performance
  changes.
- `wolfram_objective.py`: composite objective with security, performance,
  scramble diversity, and UCB1 action selection.
- `security_results.tsv`: experiment history used by the bandit.
- `program.md`, `train.py`, and `prepare.py`: inherited autoresearch/training
  materials.

The dashboard reads this component through `/api/research-tsv` and
`/api/secmetrics` when the external checkout exists at the expected path.

## How it works

```text
Windows Security log / netstat
             |
             v
  Intruder Protocol + Web-Fortress
             |
             +--> intruder-alerts.log
             |          |
             |          v
             |     JARVIS PRIME
             |          |
             |          +--> classify alert
             |          +--> semantic ChromaDB query
             |          +--> Rule-30 candidate scramble
             |          +--> known response OR generated response
             |          +--> execute mitigation
             |          +--> amend DB and persist state
             |
             +--> Quantum Analyzer
                        |
                        +--> entropy + Rule-30 chaos score
                        +--> quantum-report.json
                        +--> trigger JARVIS PRIME for elevated scores

psutil process/I/O monitor
             |
             v
      SQLite + SSE dashboard
```

### Alert-to-response lifecycle

1. A monitor identifies an event or connection that meets its threshold.
2. The component writes a structured human-readable line to
   `intruder-alerts.log`.
3. JARVIS PRIME reads only new log bytes and ignores its own generated lines.
4. The alert is classified and converted into a semantic retrieval query.
5. ChromaDB returns candidate scripts and distances.
6. Rule-30 weights produce a selection order.
7. A close match is executed; otherwise a typed response template is generated,
   persisted, and indexed for future retrieval.
8. State counters and offsets are written to `jarvis-state.json`.
9. The dashboard observes logs, reports, processes, metrics, and pipeline
   health independently.

## Quick start

### Requirements

- Windows 10/11.
- Python 3.10+ recommended.
- PowerShell 5.1+.
- Administrator PowerShell for firewall, event-log, service, and scheduled-task
  operations.
- Python packages used by the current implementation:

  ```powershell
  pip install psutil chromadb sentence-transformers
  ```

- Runtime paths are resolved from this bundled folder. The first vector query
  initializes the local collection when needed and stores runtime state under
  `runtime\`.

### Start the complete suite

From an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\jarvis-prime-launcher.ps1
```

Open [http://localhost:8765](http://localhost:8765).

The dashboard remains loopback-only. API and SSE routes require the bearer
token printed at startup and stored in `runtime\dashboard-token`.

Run hidden/background mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\jarvis-prime-launcher.ps1 -Silent
```

Install startup execution:

```powershell
powershell -ExecutionPolicy Bypass -File .\jarvis-prime-launcher.ps1 -Install
```

Stop the suite:

```powershell
powershell -ExecutionPolicy Bypass -File .\jarvis-prime-launcher.ps1 -Stop
```

### Run individual components

```powershell
# One Web-Fortress monitoring pass, or continuous monitoring
powershell -ExecutionPolicy Bypass -File .\web-fortress.ps1 -Monitor
powershell -ExecutionPolicy Bypass -File .\web-fortress.ps1 -Watch -IntervalSec 60

# Install/check/remove Intruder Protocol scheduled task
powershell -ExecutionPolicy Bypass -File .\intruder-protocol.ps1 -Install
powershell -ExecutionPolicy Bypass -File .\intruder-protocol.ps1 -Status
powershell -ExecutionPolicy Bypass -File .\intruder-protocol.ps1 -Uninstall

# Analyze current network state
python .\quantum-analyzer.py
python .\quantum-analyzer.py --port 11434 --proc ollama --pid 1234

# Process alerts continuously, once, or without executing responses
python .\jarvis_prime.py
python .\jarvis_prime.py --once
python .\jarvis_prime.py --once --dry-run

# Run the dashboard alone
python .\security-dashboard.py

# Run the search-service helper
python .\search_guardian.py
```

JARVIS PRIME uses review/dry-run mode by default, including when `--dry-run`
is omitted. Live response execution requires an explicit
`runtime\execution-policy.json` with `{"mode":"approved_live","allow_live":true}`
and should only be enabled on a disposable, elevated test host.

## Files and data

| Path | Purpose |
|---|---|
| `jarvis_prime.py` | Alert classification, retrieval, generation, and response execution |
| `web-fortress.ps1` | External listener baseline and firewall containment |
| `intruder-protocol.ps1` | Windows Security event detection and forensics |
| `quantum-analyzer.py` | Entropy/chaos threat scoring |
| `security-dashboard.py` | Local UI, SSE stream, process monitor, APIs, and persistence |
| `search_guardian.py` | On-demand Windows Search service lifecycle |
| `vector-db/` | ChromaDB initialization, taxonomy, seeds, and query helpers |
| `jarvis-responses/` | Generated and seeded response scripts |
| `graphify-out/` | Graphify graph, HTML visualization, and report |
| `intruder-alerts.log` | Shared alert and response log |
| `jarvis-prime.log` | JARVIS PRIME execution log |
| `quantum-report.json` | Latest quantum analysis report |
| `jarvis-state.json` | JARVIS offset, deduplication, and counters |
| `jarvis-pipeline-log.json` | Dashboard pipeline counters |
| `jarvis-memory.db` | Security events and metric history |
| `jarvis-io-analytics.db` | Process I/O analytics |
| `scramble-salt.json` | Optimized Rule-30 seed salt |

## Dashboard API

The dashboard is bound to loopback and requires the dashboard bearer token for
API and SSE requests. Obtain the token from `runtime\dashboard-token` or use
the `/api/token` bootstrap endpoint exposed by the local dashboard.
Useful endpoints include:

| Endpoint | Function |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/stream` | SSE `proc_table` and `io_event` stream |
| `GET /api/status` | Latest quantum report |
| `GET /api/alerts` | Recent alert-log lines |
| `GET /api/procs` | Current process snapshot |
| `GET /api/events` | Recent I/O/security events |
| `GET /api/iodata?window=3600` | Aggregated I/O analytics |
| `GET /api/memory?h=24&limit=200` | Security events and metric history |
| `GET /api/firewall` | `WF-*` firewall rules |
| `GET /api/research-tsv` | Autoresearch experiment rows |
| `GET /api/secmetrics` | Security/performance research metrics |
| `GET /api/pipeline-log` | SSE pipeline counters |
| `GET /api/graph-hypotheses` | Cached Graphify hypotheses |
| `GET /api/listeners` | Exposed listener inventory, labels, risk, and mode |
| `GET /api/all-procs` | Processes available for allow-list selection |
| `GET /api/throttle-state` | Current outbound-throttle state |
| `POST /api/run/<name>` | Run a configured dashboard job |
| `POST /api/allow-list` | Replace the process allow-list |
| `POST /api/port-control` | Block, stop, or restore a controlled port |

## Areas for improvement

### Priority 0: make the runtime safe and reproducible

1. **Fix path coupling.** Replace `Path.home()` and hard-coded
   `$HOME\Downloads`/`AndroidStudioProjects` paths with one configuration file
   or environment-driven project root. This is the largest deployment risk:
   the bundled copy and the live paths can diverge.
2. **Add an execution policy.** Generated or retrieved scripts should default
   to review or dry-run, require explicit approval for firewall/service changes,
   and record the exact command, exit code, and user identity.
3. **Harden dashboard authorization.** The dashboard now uses a persistent
   bearer token, but endpoint authorization should be extended with
   Windows-integrated identity checks, tighter CORS/Origin rules, one-time
   bootstrap protection, and stricter action-name validation.
4. **Replace broad exception swallowing.** Several monitor, dashboard, and
   PowerShell paths continue after failures without durable error reporting.
   Record structured errors and distinguish unavailable telemetry from a clean
   result.
5. **Add dependency and startup checks.** Fail clearly when `psutil`, ChromaDB,
   the embedding model, vector collection, or autoresearch checkout is absent.

### Priority 1: improve detection correctness

1. Parse `netstat` and event records with robust structured APIs where possible;
   current text parsing is locale- and IPv6-sensitive.
2. Normalize duplicate ports and preserve listener address, protocol, process
   path, and timestamp in reports.
3. Add allow-list review before blocking system, development, container, and
   enterprise software ports.
4. Make alert thresholds configurable and testable instead of embedded in
   scripts.
5. Add rollback commands for every generated firewall rule, service change, and
   scheduled task.
6. Add signed response artifacts, hash verification, and an audit trail for
   vector-DB amendments.

### Priority 2: improve architecture and operations

1. Split the dashboard into a service/API layer and static UI; move the large
   inline HTML/JavaScript document into versioned assets.
2. Use a single structured event schema instead of sharing free-form log text.
3. Replace per-thread SQLite connections and silent retention failures with a
   managed storage layer and health metrics.
4. Add bounded queues/backpressure for SSE clients and explicit dropped-event
   counters.
5. Add unit tests for threat classification, Rule-30 determinism, score
   boundaries, state recovery, path parsing, and dry-run guarantees.
6. Add integration tests using synthetic Windows event and `netstat` fixtures.
7. Pin dependencies and add a supported Python matrix, packaging metadata, and
   a clean install script.
8. Separate the external autoresearch repository from runtime discovery through
   an explicit plugin/configuration interface.

### Graphify-derived documentation gaps

Graphify reported weakly connected communities, 67 isolated nodes, and seven
inferred edges. Those findings suggest:

- undocumented contracts between the dashboard, autoresearch, and Graphify;
- missing edges around generated scripts and persistent data stores;
- low cohesion in the performance-analysis and model-training clusters;
- inferred relationships around tokenizer/model components that should not be
  treated as runtime guarantees until verified;
- no single authoritative configuration or dependency manifest.

## Current limitations

- Windows-only operational controls; Linux examples in the vector corpus are
  not proof that the runtime is cross-platform.
- The dashboard is local-only but unauthenticated.
- Firewall rules are not automatically rolled back.
- The vector DB is local and semantic matches are not a security proof.
- Rule-30 scrambling changes selection order but does not validate whether a
  mitigation is safe or appropriate.
- The current snapshot contains historical runtime artifacts and generated
  scripts; inspect timestamps and state before using them as current telemetry.
- Graphify's report was generated from a broader merged corpus, so some nodes
  refer to files outside this directory.

## Graphify maintenance

The checked-in Graphify artifacts are in `graphify-out/`:

```powershell
# Inspect the existing graph
graphify query "alert to mitigation data flow" `
  --graph .\graphify-out\graph.json

# Rebuild after source changes (command depends on the Graphify installation)
graphify update .
```

Review `graphify-out\GRAPH_REPORT.md` and `graphify-out\graph.html` after
regenerating. Treat inferred edges as hypotheses, not implementation facts.

## Standalone Windows controller

The reproducible Windows build is emitted at
`dist\JarvisPrime\JarvisPrime.exe`. It opens a dedicated JARVIS PRIME control
window, starts the authenticated loopback dashboard and defensive watchers,
and keeps the existing `review_dry_run` policy enforced by default. It does
not silently elevate and it does not bundle dashboard tokens or API keys.

```powershell
# Validate the packaged runtime without opening the control window
.\dist\JarvisPrime\JarvisPrime.exe --self-test

# Install/remove per-user startup (no administrator permission required)
.\dist\JarvisPrime\JarvisPrime.exe --install-startup
.\dist\JarvisPrime\JarvisPrime.exe --uninstall-startup
```

Startup uses the signed-in user's Startup folder rather than a highest-
privilege scheduled task. Live firewall or containment actions still require
an explicit `approved_live` execution policy and the appropriate Windows
permissions; the controller never enables those settings automatically.

## License and provenance

JARVIS PRIME is distributed under the
[MIT License](LICENSE).

The protective-script corpus includes defensive examples adapted from or
inspired by Windows, Linux, identity, backup, network, and security guidance.
Review and independently validate third-party guidance, generated scripts, and
operational changes before use. Active defense, firewall changes, process
termination, service changes, and scheduled tasks require appropriate
authorization and Windows permissions.
