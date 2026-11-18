# JARVIS PRIME — grouped index

Live system runs from `C:\Users\yungk\` (do not move while running). This hub
groups everything logically; `autoresearch/` here is a junction to the real repo.

## Origin & dependency bundle (copied 2026-06-28)
**Origin file:** `jarvis_prime.py` — "JARVIS PRIME — Intelligence-Response Bridge"
(created 2026-06-25). Entry point: `python jarvis_prime.py [--once] [--dry-run]`.

This folder now holds a **complete static copy** of every file the engine
functions with (38.9 MB, 46 files). It is a snapshot — the **live system still
runs from `~/` by absolute path**, so this bundle does not auto-update.

Dependency map (what `jarvis_prime.py` touches):
| Bundle file | Relationship |
|---|---|
| scramble-salt.json | read — Wolfram CA scramble salt (loaded next to engine) |
| intruder-protocol.ps1 → intruder-alerts.log | producer → input log (tailed) |
| quantum-analyzer.py → quantum-report.json | subprocess → output report (read) |
| web-fortress.ps1, search_guardian.py | sibling defense daemons |
| security-dashboard.py | GUI (localhost:8765) over the same logs/state |
| jarvis-state.json | read/write — seen-hashes, amendment_count |
| jarvis-prime.log | write — engine log |
| jarvis-responses/ | write — generated mitigation scripts |
| jarvis-memory.db, jarvis-io-analytics.db, jarvis-pipeline-log.json | data stores |
| vector-db/cybersec_protective_scripts_vector_db.py + _db/ | ChromaDB mitigation corpus (was in ~/Downloads) |
| jarvis-prime-launcher.ps1 / .bat | suite launchers |

Re-sync the bundle later: re-run the copy, or convert to a true self-contained
app (move + repoint all `~/` paths) when the suite is stopped.

## Core (C:\Users\yungk\)
| File | Role |
|---|---|
| jarvis_prime.py | main engine (live-patched by the research loop) |
| jarvis-prime-launcher.ps1 / jarvis-prime-start.bat | launchers |
| jarvis-state.json | runtime state (amendment_count, etc.) |
| jarvis-prime.log | engine log (metrics source) |
| jarvis-memory.db / jarvis-io-analytics.db | memory + IO analytics |
| jarvis-pipeline-log.json | pipeline trace |
| jarvis-responses/ | generated responses |
| intruder-alerts.log / quantum-report.json | security inputs to metrics |

Running processes (verified 2026-06-25): search_guardian.py, security-dashboard.py, dashboard PID in .jarvis-dashboard.pid.

## Security suite as one program
**GUI:** web dashboard at **http://localhost:8765** (served by `security-dashboard.py`;
SSE stream + JS auto-refresh, backed by `KernelMonitor` ticking on a
**quantized 1.0s clock grid** — phase-locked, no drift).

**Start everything:** `powershell -ExecutionPolicy Bypass -File jarvis-prime-launcher.ps1`
Grouped components (in start order): WEB-FORTRESS, INTRUDER, DASHBOARD,
SEARCH-GUARD, QUANTUM, JARVIS-PRIME, AUTORESEARCH.
Stop all: `jarvis-prime-launcher.ps1 -Stop`

**Persistence (survives reset):** Startup-folder shortcut
`…\Startup\JARVIS-PRIME-Suite.lnk` (current user, hidden, no admin).
For elevated/firewall persistence run once from an **admin** shell:
`jarvis-prime-launcher.ps1 -Install` (registers AtLogOn task, RunLevel Highest).

## Autoresearch loop (./autoresearch → AndroidStudioProjects\autoresearch\)
| File | Role |
|---|---|
| security_research_loop.py | the keep/revert recursive loop |
| violation_tracker.py | computes security metrics from logs |
| perf_researcher.py | processing/perf metrics + auto-fixes |
| **wolfram_objective.py** | **Wolfram-derived composite J + entropy diversity + UCB1 bandit** |
| **WOLFRAM_ALGORITHM.md** | **the algorithm write-up** |
| security_results.tsv | iteration history (feeds the bandit) |
| train.py / prepare.py / program.md | original Karpathy autoresearch (LLM) |

## graphify
- **`JARVIS-PRIME\graphify-out\graph.json`** — **UNIFIED graph: 242 nodes / 327 edges, 20 communities**, merged from home + autoresearch. Browse `graph.html`, read `GRAPH_REPORT.md`.
  - Query: `graphify query "<q>" --graph JARVIS-PRIME\graphify-out\graph.json`
  - Rebuild after code changes: `graphify update AndroidStudioProjects\autoresearch` then `graphify merge-graphs C:\Users\yungk\graphify-out\graph.json AndroidStudioProjects\autoresearch\graphify-out\graph.json --out JARVIS-PRIME\graphify-out\graph.json`
- `C:\Users\yungk\graphify-out\` — home graph (source) · `autoresearch\graphify-out\` — loop graph (source)
- `C:\Users\yungk\.graphify\` — global graphify cache
- No `graphify-windows` database exists; this unified graph is its replacement.
