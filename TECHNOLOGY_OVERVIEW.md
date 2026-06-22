# SupplyScan Technology Overview

SupplyScan is a supply-chain security tool that scans Python and npm packages for suspicious behavior, stores scan history, and can generate AI-assisted explanations for reviewers.

## What the project is built from

| Technology | Why it is used | Where it is used |
| --- | --- | --- |
| Python 3.11 | Main language for scanner logic, detectors, persistence, and CLI automation. | `supplyscan/` |
| Click | Clean command-line interface for scan, history, dashboard, init, and hook removal commands. | `supplyscan/cli/main.py` |
| Rich | Better terminal output for scan reports and history tables. | `supplyscan/cli/main.py` |
| Pydantic | Strict data models for scan targets, detector results, and threat explanations. | `supplyscan/models.py` |
| FastAPI | Local dashboard API and HTML pages with simple async routes. | `supplyscan/dashboard/app.py` |
| Uvicorn | Runs the FastAPI dashboard server. | `supplyscan/cli/main.py` |
| SQLModel + SQLite | Lightweight local storage for scan history and stats. | `supplyscan/db/store.py` |
| platformdirs | Stores history in a user-friendly per-platform data path. | `supplyscan/db/store.py` |
| httpx | Calls external AI explainer APIs. | `supplyscan/ai/opencode_explainer.py` |
| Anthropic SDK | Claude provider support for AI explanations. | `supplyscan/ai/claude_explainer.py` and `pyproject.toml` |
| Semgrep | Pattern-based security rules for suspicious install-time code. | `supplyscan/detectors/semgrep_detector.py` and `supplyscan/rules/semgrep/supply_chain.yml` |
| YARA | Signature-style malware detection rules. | `supplyscan/detectors/yara_detector.py` and `supplyscan/rules/malware.yar` |
| LibCST | Safer Python AST-style analysis for setup and package code. | `supplyscan/detectors/ast_detector.py` |
| packaging | Version and requirement handling for package resolution. | `supplyscan/core/version_resolver.py` and `supplyscan/cli/main.py` |
| React + Next.js + TypeScript | Interactive frontend for the dashboard and scan details. | `frontend/src/` |
| Tailwind CSS | Fast utility styling for the dashboard UI. | `frontend/src/app/globals.css` and frontend components |
| shadcn/ui + lucide-react | Reusable UI primitives and icons. | `frontend/src/components/ui/` and `frontend/src/components/scan-detail-modal.tsx` |
| sonner | Toast notifications in the frontend. | `frontend/src/components/ui/sonner.tsx` |
| Node.js | npm hook execution and frontend runtime. | `supplyscan/hooks/npm_hook.js` and `frontend/package.json` |
| pytest | Unit and behavior tests. | `tests/` |

## Main project flow

1. A user runs `supplyscan check`, `supplyscan history`, or opens the dashboard.
2. The CLI resolves the target package and version.
3. `SupplyScanScanner` runs the detector stack, dynamically filtered by scan mode (Zero-Day Behavioral vs. Known CVEs) in the Sandbox configuration.
4. If findings exist, the AI explainer router generates a plain-English explanation. Any provider API error (rate limits, key expiration, or connection drops) is caught and isolated to prevent scanner crashes, safely resolving to a deterministic local fallback.
5. The final report is saved to SQLite.
6. The dashboard and frontend read the same stored history and stats.

## Core modules and responsibilities

- `supplyscan/core/scanner.py`: orchestrates all detectors, applies scan mode filtering, isolates AI explainer execution failures, and builds a final `ScanReport`.
- `supplyscan/detectors/`: contains the actual security checks, such as typosquatting, CVE lookup, entropy, AST analysis, network-call detection, Semgrep, YARA, and maintainer checks.
- `supplyscan/ai/`: routes to Claude or OpenCode.ai and falls back to a deterministic explanation when AI is unavailable.
- `supplyscan/db/store.py`: writes and reads scan history.
- `supplyscan/dashboard/app.py`: serves the local dashboard and JSON API.
- `frontend/src/lib/api.ts`: consumes backend endpoints and normalizes responses for the UI.
- `frontend/src/components/scan-detail-modal.tsx`: shows a full scan breakdown with severity, signals, and explanation.
- `supplyscan/hooks/npm_hook.js`: blocks or forwards npm installs through SupplyScan.

## Why these technologies fit

- Python fits security tooling well because it can inspect package metadata, run detectors, and integrate with package-manager hooks easily.
- Click and Rich make the command line useful instead of noisy.
- FastAPI gives the project a small but capable backend for local scanning and dashboard views.
- SQLite keeps scan history local, portable, and easy to ship without a separate database server.
- React + Next.js + TypeScript make the dashboard easier to maintain and safer to extend.
- Semgrep, YARA, LibCST, and the custom detectors cover different attack styles instead of relying on only one signal source.
- AI explanations improve reviewer speed, but the project still works offline because it has deterministic fallbacks.

## Testing and validation

- `tests/test_phase1.py` and `tests/test_version_resolver.py` cover core behavior, package resolution, and AI explainer exception isolation robustness.
- `tests/malicious/` contains sample malicious packages used to validate the detector pipeline.
- The project also ships rules and hook code in `supplyscan/rules/` and `supplyscan/hooks/` so the security path is testable end to end.

## Configuration

- `OPENCODE_API_KEY`: enables OpenCode.ai explanations.
- `CLAUDE_API_KEY`: enables Claude explanations and is preferred when present.
- `OPENCODE_MODEL`: overrides the default OpenCode model.
- `config.env`: local file that can store these values for development.

## Short summary

SupplyScan combines a Python scanner, rule-based security detectors, optional AI explanations, local SQLite history, and a Next.js dashboard into one workflow so package risks can be reviewed quickly.
