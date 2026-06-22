"""FastAPI dashboard for SupplyScan scan history and manual scans."""

from __future__ import annotations

import html
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from supplyscan.ai.claude_explainer import is_provider_failure_explanation
from supplyscan.ai.explainer_router import build_explainer_from_env
from supplyscan.core.scanner import SupplyScanScanner
from supplyscan.core.version_resolver import resolve_latest_version
from supplyscan.db import ScanStore, default_store_path
from supplyscan.models import ScanReport, ScanTarget, Severity


app = FastAPI(title="SupplyScan Dashboard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Render recent scan history with metrics and live scan controls."""

    store = ScanStore.default()
    reports = await store.load_recent(20)
    stats = await store.load_stats()
    body = render_page("SupplyScan Command Center", reports, "", stats)
    return HTMLResponse(body)


@app.get("/scan/{package}", response_model=None)
async def scan_package(
    package: str,
    request: Request,
    version: str | None = Query(default=None),
    source: str = Query(default="dashboard"),
    mode: str = Query(default="all"),
    response_format: str | None = Query(default=None, alias="format"),
) -> HTMLResponse | JSONResponse:
    """Run a package scan and return HTML or JSON based on the request."""

    report = await run_dashboard_scan(package, version, source, mode=mode)
    if wants_json_response(request, response_format):
        return JSONResponse(report_to_json(report))

    store = ScanStore.default()
    reports = await store.load_recent(20)
    stats = await store.load_stats()
    body = render_page(
        f"Scan Result: {package}",
        reports,
        render_scan_result(report),
        stats,
    )
    return HTMLResponse(body)


@app.get("/api/stats", response_model=None)
async def api_stats() -> JSONResponse:
    """Return aggregate scan statistics for the frontend."""

    stats = await ScanStore.default().load_stats()
    return JSONResponse(
        {
            "total": int(stats["total_scans"]),
            "threats": int(stats["threats_blocked"]),
            "clean": int(stats["clean_packages"]),
            "avg_ms": float(stats["avg_ms"]),
        }
    )


@app.get("/api/history", response_model=None)
async def api_history(limit: int = Query(default=20, ge=1, le=200)) -> JSONResponse:
    """Return recent scan history as JSON for the frontend."""

    reports = await ScanStore.default().load_recent(limit)
    return JSONResponse({"reports": [report_to_json(report) for report in reports], "items": [report_to_json(report) for report in reports]})


@app.get("/api/scan/{package}", response_model=None)
async def api_scan_package(
    package: str,
    version: str | None = Query(default=None),
    source: str = Query(default="dashboard-api"),
    mode: str = Query(default="all"),
) -> JSONResponse:
    """Run a package scan and return JSON for live dashboard updates."""

    report = await run_dashboard_scan(package, version, source, mode=mode)
    store = ScanStore.default()
    reports = await store.load_recent(20)
    stats = await store.load_stats()
    return JSONResponse(
        {
            "report": report_to_json(report),
            "stats": stats_to_json(stats),
            "history_html": render_history_table(reports),
            "result_html": render_scan_result(report),
        }
    )


async def run_dashboard_scan(package: str, version: str | None, source: str, mode: str = "all") -> ScanReport:
    """Run a dashboard scan and persist it to history."""

    scanner = SupplyScanScanner.with_mode_detectors(mode=mode, explainer=build_explainer_from_env())
    normalized_source = "auto" if source in {"dashboard", "dashboard-api"} else source
    resolved = await resolve_latest_version(
        ScanTarget(name=package, version=version, source=normalized_source)
    )
    if resolved.warning and "does not exist" in resolved.warning:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=resolved.warning)
    report = await scanner.scan(resolved.target)
    
    metadata = {**report.metadata, "scan_mode": mode}
    if resolved.exists_in_both:
        metadata["dual_registry"] = True

    report = report.model_copy(update={"metadata": metadata})
    await ScanStore.default().save(report)
    return report


def render_page(
    title: str,
    reports: list[ScanReport],
    result_panel: str,
    stats: dict[str, int | float],
) -> str:
    """Render a complete dashboard HTML page."""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} - SupplyScan</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f5f7fb;
      --surface: #ffffff;
      --surface-2: #eef2f7;
      --text: #172033;
      --muted: #64748b;
      --line: #dbe3ef;
      --accent: #0f766e;
      --accent-2: #2563eb;
      --danger: #dc2626;
      --danger-bg: #fff1f2;
      --clean: #15803d;
      --clean-bg: #ecfdf5;
      --warn: #b45309;
      --warn-bg: #fffbeb;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; }}
    .shell {{ max-width: 1180px; margin: 0 auto; padding: 32px; }}
    header {{ display: grid; grid-template-columns: 1fr auto; gap: 20px; align-items: end; margin-bottom: 24px; }}
    .eyebrow {{ color: var(--accent); font-size: 12px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }}
    h1 {{ font-size: 34px; line-height: 1.1; margin: 6px 0 8px; letter-spacing: 0; }}
    .subtitle {{ margin: 0; color: var(--muted); max-width: 680px; }}
    .scan-form {{ display: grid; grid-template-columns: minmax(220px, 1fr) 120px auto; gap: 8px; background: var(--surface); border: 1px solid var(--line); padding: 10px; border-radius: 8px; box-shadow: 0 14px 40px rgba(15,23,42,.08); }}
    input {{ width: 100%; padding: 11px 12px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); color: var(--text); font: inherit; }}
    button, a.button {{ padding: 11px 14px; border: 0; border-radius: 6px; background: var(--accent); color: white; text-decoration: none; cursor: pointer; font-weight: 750; }}
    button:disabled {{ opacity: .65; cursor: progress; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 18px; }}
    .metric {{ background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 18px; box-shadow: 0 14px 32px rgba(15,23,42,.06); }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; font-weight: 750; }}
    .metric strong {{ display: block; margin-top: 6px; font-size: 34px; letter-spacing: 0; }}
    .metric.clean strong {{ color: var(--clean); }}
    .metric.threat strong {{ color: var(--danger); }}
    .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 18px; margin-bottom: 18px; box-shadow: 0 14px 32px rgba(15,23,42,.06); }}
    .panel h2 {{ margin: 0 0 12px; font-size: 18px; }}
    .status-line {{ color: var(--muted); min-height: 22px; margin: 0 0 14px; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0 8px; }}
    th {{ text-align: left; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; padding: 0 12px 4px; }}
    td {{ padding: 13px 12px; background: var(--surface); border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); vertical-align: top; }}
    td:first-child {{ border-left: 1px solid var(--line); border-radius: 8px 0 0 8px; }}
    td:last-child {{ border-right: 1px solid var(--line); border-radius: 0 8px 8px 0; }}
    tr.clean-row td {{ background: var(--clean-bg); }}
    tr.threat-row td {{ background: var(--danger-bg); }}
    tr.warn-row td {{ background: var(--warn-bg); }}
    .pkg a {{ color: var(--accent-2); font-weight: 800; text-decoration: none; }}
    .badge {{ display: inline-flex; min-width: 82px; justify-content: center; padding: 5px 8px; border-radius: 999px; font-size: 12px; font-weight: 900; }}
    .sev-INFO {{ background: #dcfce7; color: #166534; }}
    .sev-LOW {{ background: #fef3c7; color: #92400e; }}
    .sev-MEDIUM {{ background: #fed7aa; color: #9a3412; }}
    .sev-HIGH {{ background: #fee2e2; color: #991b1b; }}
    .sev-CRITICAL {{ background: #7f1d1d; color: #fee2e2; }}
    .signals {{ margin: 8px 0 0; padding-left: 20px; }}
    .ai {{ margin-top: 14px; padding: 12px; border-left: 4px solid var(--accent-2); background: var(--surface-2); border-radius: 6px; }}
    .ai p {{ white-space: pre-wrap; margin: 0; }}
    .empty {{ color: var(--muted); padding: 18px; border: 1px dashed var(--line); border-radius: 8px; }}
    @media (max-width: 850px) {{
      .shell {{ padding: 20px; }}
      header {{ grid-template-columns: 1fr; }}
      .scan-form {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: 1fr; }}
      table {{ font-size: 14px; }}
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0b1020;
        --surface: #141b2d;
        --surface-2: #101827;
        --text: #e5edf9;
        --muted: #9aa8bd;
        --line: #263246;
        --accent: #2dd4bf;
        --accent-2: #60a5fa;
        --danger: #fb7185;
        --danger-bg: #33141d;
        --clean: #4ade80;
        --clean-bg: #10281c;
        --warn-bg: #2b2112;
      }}
      .metric, .panel, .scan-form {{ box-shadow: none; }}
      .sev-INFO {{ background: #064e3b; color: #bbf7d0; }}
      .sev-LOW {{ background: #422006; color: #fde68a; }}
      .sev-MEDIUM {{ background: #7c2d12; color: #fed7aa; }}
      .sev-HIGH {{ background: #7f1d1d; color: #fecaca; }}
      .sev-CRITICAL {{ background: #fecaca; color: #7f1d1d; }}
    }}
  </style>
</head>
<body>
<main class="shell">
  <header>
    <div>
      <div class="eyebrow">Autonomous package defense</div>
      <h1>{html.escape(title)}</h1>
      <p class="subtitle">Live supply-chain scan history from {html.escape(str(default_store_path()))}</p>
    </div>
    <form id="scan-form" class="scan-form">
      <input id="package-input" name="package" placeholder="Package name, e.g. colourama" autocomplete="off">
      <input id="version-input" name="version" placeholder="Version">
      <button id="scan-button" type="submit">Scan</button>
    </form>
  </header>
  <section id="metrics" class="grid">{render_metric_cards(stats)}</section>
  <p id="status-line" class="status-line"></p>
  <section id="result-panel">{result_panel}</section>
  <section class="panel">
    <h2>Recent Scans</h2>
    <div id="history-table">{render_history_table(reports)}</div>
  </section>
</main>
<script>
const form = document.getElementById('scan-form');
const packageInput = document.getElementById('package-input');
const versionInput = document.getElementById('version-input');
const button = document.getElementById('scan-button');
const statusLine = document.getElementById('status-line');
const resultPanel = document.getElementById('result-panel');
const historyTable = document.getElementById('history-table');
const metrics = document.getElementById('metrics');

function metricCards(stats) {{
  return `
    <article class="metric"><span>Total scans</span><strong>${{stats.total_scans}}</strong></article>
    <article class="metric threat"><span>Threats blocked</span><strong>${{stats.threats_blocked}}</strong></article>
    <article class="metric clean"><span>Clean packages</span><strong>${{stats.clean_packages}}</strong></article>
  `;
}}

form.addEventListener('submit', async (event) => {{
  event.preventDefault();
  const packageName = packageInput.value.trim();
  if (!packageName) {{
    statusLine.textContent = 'Enter a package name to scan.';
    return;
  }}
  const version = versionInput.value.trim();
  const query = version ? `?version=${{encodeURIComponent(version)}}` : '';
  button.disabled = true;
  statusLine.textContent = `Scanning ${{packageName}}...`;
  try {{
    const response = await fetch(`/api/scan/${{encodeURIComponent(packageName)}}${{query}}`);
    if (!response.ok) {{
      throw new Error(`HTTP ${{response.status}}`);
    }}
    const data = await response.json();
    resultPanel.innerHTML = data.result_html;
    historyTable.innerHTML = data.history_html;
    metrics.innerHTML = metricCards(data.stats);
    statusLine.textContent = `${{data.report.target.name}} scanned in ${{data.report.duration_ms}}ms.`;
  }} catch (error) {{
    statusLine.textContent = `Scan failed: ${{error.message}}`;
  }} finally {{
    button.disabled = false;
  }}
}});
</script>
</body>
</html>"""


def render_metric_cards(stats: dict[str, int | float]) -> str:
    """Render top-level dashboard metric cards."""

    return (
        f"<article class='metric'><span>Total scans</span><strong>{stats['total_scans']}</strong></article>"
        f"<article class='metric threat'><span>Threats blocked</span><strong>{stats['threats_blocked']}</strong></article>"
        f"<article class='metric clean'><span>Clean packages</span><strong>{stats['clean_packages']}</strong></article>"
    )


def render_history_table(reports: list[ScanReport]) -> str:
    """Render scan history table HTML."""

    if not reports:
        return "<div class='empty'>No scan history yet. Run a live scan to populate the table.</div>"
    rows = []
    for report in reports:
        package = html.escape(report.target.name)
        package_url = quote(report.target.name, safe="")
        version = html.escape(report.target.version or "")
        severity = html.escape(report.overall_severity.value)
        row_class = row_class_for_report(report)
        rows.append(
            f"<tr class='{row_class}'>"
            f"<td>{html.escape(report.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}</td>"
            f"<td class='pkg'><a href='/scan/{package_url}'>{package}</a></td>"
            f"<td>{version or 'latest'}</td>"
            f"<td><span class='badge sev-{severity}'>{severity}</span></td>"
            f"<td>{'Clean' if report.clean else 'Threat'}</td>"
            f"<td>{report.duration_ms}ms</td>"
            "</tr>"
        )
    return (
        "<table>"
        "<thead><tr><th>Scanned At</th><th>Package</th><th>Version</th><th>Severity</th><th>Status</th><th>Duration</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def render_scan_result(report: ScanReport) -> str:
    """Render a single scan result HTML panel."""

    severity = html.escape(report.overall_severity.value)
    findings = []
    for detector_result in report.detector_results:
        for finding in detector_result.findings:
            findings.append(
                f"<li><strong>{html.escape(detector_result.name)}</strong>: {html.escape(finding)}</li>"
            )
    finding_html = "<ul class='signals'>" + "".join(findings) + "</ul>" if findings else "<p>No detector findings.</p>"
    explanation = ""
    if report.explanation is not None:
        explanation = (
            "<div class='ai'>"
            "<strong>AI Analysis</strong>"
            f"<p>{html.escape(report.explanation.explanation)}</p>"
            f"<p><strong>Recommended action:</strong> {html.escape(report.explanation.recommended_action)}</p>"
            "</div>"
        )
    status = "Clean package" if report.clean else "Threat detected"
    return (
        "<section class='panel'>"
        f"<h2>{html.escape(report.target.name)} <span class='badge sev-{severity}'>{severity}</span></h2>"
        f"<p><strong>Version:</strong> {html.escape(report.target.version or 'latest')}</p>"
        f"<p><strong>Status:</strong> {status}</p>"
        f"<p><strong>Duration:</strong> {report.duration_ms}ms</p>"
        "<h2>Signals</h2>"
        f"{finding_html}"
        f"{explanation}"
        "</section>"
    )


def row_class_for_report(report: ScanReport) -> str:
    """Return a CSS row class for a scan report."""

    if report.clean:
        return "clean-row"
    if report.overall_severity in {Severity.CRITICAL, Severity.HIGH}:
        return "threat-row"
    return "warn-row"


def report_to_json(report: ScanReport) -> dict[str, Any]:
    """Serialize a scan report for the dashboard API."""

    package_name = report.target.name
    version = report.target.version or "latest"
    severity = report.overall_severity.value
    return {
        "package": package_name,
        "name": package_name,
        "version": version,
        "source": report.target.source,
        "target": {
            "name": package_name,
            "version": report.target.version,
            "source": report.target.source,
        },
        "scanned_at": report.scanned_at.isoformat(),
        "timestamp": report.scanned_at.isoformat(),
        "duration_ms": report.duration_ms,
        "clean": report.clean,
        "isClean": report.clean,
        "overall_severity": severity,
        "severity": severity,
        "status": "Allowed" if report.clean else "Blocked",
        "ai_analysis_used": report.explanation is not None
        and not is_provider_failure_explanation(report.explanation),
        "metadata": report.metadata,
        "detector_results": [
            {
                "name": result.name,
                "severity": result.severity.value,
                "findings": result.findings,
                "evidence": [
                    {"label": item.label, "value": item.value}
                    for item in result.evidence
                ],
            }
            for result in report.detector_results
        ],
        "signals": [
            {
                "message": finding,
                "severity": result.severity.value,
                "detector": result.name,
            }
            for result in report.detector_results
            for finding in result.findings
        ],
        "explanation": (
            {
                "severity": report.explanation.severity.value,
                "explanation": report.explanation.explanation,
                "recommended_action": report.explanation.recommended_action,
            }
            if report.explanation is not None
            else None
        ),
    }


def stats_to_json(stats: dict[str, int | float]) -> dict[str, int | float]:
    """Return JSON-ready stats."""

    return {
        "total": int(stats["total_scans"]),
        "threats": int(stats["threats_blocked"]),
        "clean": int(stats["clean_packages"]),
        "avg_ms": float(stats["avg_ms"]),
        "total_scans": int(stats["total_scans"]),
        "threats_blocked": int(stats["threats_blocked"]),
        "clean_packages": int(stats["clean_packages"]),
    }


def wants_json_response(request: Request, response_format: str | None) -> bool:
    """Return whether a scan route should emit JSON instead of HTML."""

    if response_format == "json":
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept.lower()
