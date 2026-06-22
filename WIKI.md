# SupplyScan Wiki & Technical Architecture Guide

Welcome to the SupplyScan technical wiki. This document provides a deep dive into the inner workings, detection mechanisms, and integration capabilities of the SupplyScan platform.

---

## Table of Contents
1. [Overview](#1-overview)
2. [Detector Architecture (The 9-Layer Stack)](#2-detector-architecture-the-9-layer-stack)
3. [Interception Hooks (Pip & NPM)](#3-interception-hooks-pip--npm)
4. [Reusable GitHub Actions Pipeline](#4-reusable-github-actions-pipeline)
5. [AI Routing & Explainer Fallbacks](#5-ai-routing--explainer-fallbacks)
6. [Hosting & Deployment Guide](#6-hosting--deployment-guide)

---

## 1. Overview
SupplyScan is an autonomous dependency firewall. Traditional security tools (SCA) rely strictly on historical CVE databases, meaning they are blind to zero-day attacks, typosquats, and malicious maintainer takeovers. SupplyScan intercepts installs at the client level and runs a hybrid static and behavioral analysis pipeline before allowing dependencies to write to disk.

---

## 2. Detector Architecture (The 9-Layer Stack)
When a package is scanned, `SupplyScanScanner` runs these detectors concurrently using Python's `asyncio`. The set of active detectors can be filtered dynamically depending on the selected scan mode (Zero-Day Behavioral vs. Known CVE Database audits) configured through the Threat Sandbox interface:

| Layer | File / Module | Core Detection Logic |
| :--- | :--- | :--- |
| **CST AST Analysis** | [ast_detector.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/ast_detector.py) | Parses Python source trees using `libCST` to identify dynamic `eval`/`exec` calls with non-literal inputs, `subprocess` calls with `shell=True`, and writes targeting sensitive paths (e.g. `/etc/`, `.ssh/`). |
| **CVE Advisor** | [cve_detector.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/cve_detector.py) | Concurrently queries OSV, PyPI, and GitHub Advisory APIs using semantic version checking to identify known issues. |
| **Obfuscation & Entropy** | [entropy_detector.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/entropy_detector.py) | Calculates Shannon entropy of string tokens. Detects hex-encoded strings and base64 payloads representing hidden scripts. |
| **Signature Matching** | [yara_detector.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/yara_detector.py) | Compiles and scans files against [malware.yar](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/rules/malware.yar) rules, flagging standard shellcode patterns and reverse shells. |
| **Typosquatting** | [typosquat.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/typosquat.py) | Compares package names using Levenshtein distance against a built-in popular list. Translates Unicode homoglyphs to defeat visual mimicry. |
| **Maintainer Anomaly** | [maintainer.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/maintainer.py) | Analyzes package registry metadata to find high-risk activities like single maintainer swaps on popular packages, dormant projects returning after years, or NPM quarantine blocks. |
| **Network Calls** | [network_detector.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/network_detector.py) | Scans scripts and files for standard connection APIs (`socket`, `urllib`, `fetch`, `dns.lookup`) to identify install-time data exfiltration. |
| **Static Semgrep Rules**| [semgrep_detector.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/semgrep_detector.py) | Runs custom rules defined in [supply_chain.yml](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/rules/semgrep/supply_chain.yml) via Semgrep CLI. |
| **Threat Feed Matcher** | [local_feed.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/detectors/local_feed.py) | Matches packages against a locally cached, auto-syncing copy of ProjectDiscovery's `depx` malicious packages export. |

---

## 3. Interception Hooks (Pip & NPM)
When a developer runs a setup command, hooks intercept the execution before installation begins:

### Python / Pip
1. When you run `supplyscan init`, the [HookManager](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/hooks/hook_manager.py) injects a marked bootstrapper into python's standard library `sitecustomize.py`.
2. Every subsequent `pip install` imports `sitecustomize.py` at boot time.
3. The hook parses the command arguments, resolves the package being installed, and invokes `supplyscan check` in a subprocess.
4. If a critical or high-severity threat is flagged, the hook prints an error panel and calls `SystemExit(1)` to abort the pip command.

### Node / NPM
1. The hook manager inserts a `preinstall` setting into the global `~/.npmrc` config file referencing [npm_hook.js](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/hooks/npm_hook.js).
2. For every `npm install` command (including dependency updates), NPM runs the preinstall hook.
3. The hook checks `process.env.npm_package_name`, executes the scan, and halts installation on threat detection.

---

## 4. Reusable GitHub Actions Pipeline
You can configure any external repository to run automated scans without replicating the codebase.

The workflow [.github/workflows/supplyscan.yml](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/.github/workflows/supplyscan.yml) exports a `workflow_call:` event trigger.

### Dev X Setup
To protect their repository `xyz`, Dev X just creates `.github/workflows/audit.yml` pointing to your repository:
```yaml
name: Dependency Scan

on:
  pull_request:

jobs:
  run-audit:
    uses: <your-github-username>/SupplyScan/.github/workflows/supplyscan.yml@main
```

---

## 5. AI Routing & Explainer Fallbacks
When a threat is detected, the AI router ([explainer_router.py](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/ai/explainer_router.py)) handles explanation generation:

- **Routing Order:** 
  1. Searches for `CLAUDE_API_KEY` (utilizes Claude-3.5-Sonnet).
  2. Falls back to `OPENCODE_API_KEY` (utilizes OpenCode free models starting with `deepseek-v4-flash-free`).
  3. Offline mode (returns raw findings).
- **Resilient Fallback:** If API limits are exceeded or the network is offline, the code invokes [local_failure_explanation](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/supplyscan/ai/claude_explainer.py#L166-L184) which constructs a deterministic explanation using top detector findings.
- **Runtime Isolation:** The core orchestrator in `scanner.py` runs the entire explainer routing call inside a `try...except Exception` block. Any unexpected runtime error (e.g. rate-limit blocks, credential failures, or provider offline states) is logged and safely isolated, ensuring the package scan successfully yields its findings rather than crashing with an HTTP 500 API error.

---

## 6. Hosting & Deployment Guide

### Running locally with Docker
A [Dockerfile](file:///C:/Users/windo/OneDrive/Desktop/SupplyScan/Dockerfile) is included in the project root. You can build and run the FastAPI server locally using:
```bash
docker build -t supplyscan-backend .
docker run -p 7860:7860 -e OPENCODE_API_KEY="your-key" supplyscan-backend
```

### Free Deployment Setup (No Card Required)
- **FastAPI Backend:** Deploy to **Hugging Face Spaces** using the **Docker** SDK template (Blank). It runs the container on port `7860` completely for free.
- **Next.js Frontend:** Deploy the `frontend/` subdirectory to **Vercel** for free. Add the environment variable `NEXT_PUBLIC_API_URL` pointing to your Hugging Face Space URL.
