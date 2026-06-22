"""Click entry point for SupplyScan."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from supplyscan.ai.claude_explainer import is_provider_failure_explanation
from supplyscan.ai.explainer_router import build_explainer_from_env
from supplyscan.core.scanner import SupplyScanScanner
from supplyscan.core.version_resolver import resolve_latest_versions
from supplyscan.db import ScanStore, default_store_path
from supplyscan.hooks.hook_manager import HookManager, HookReport
from supplyscan.models import ScanReport, ScanTarget, Severity


@click.group()
def main() -> None:
    """SupplyScan command line interface."""


@main.command()
@click.argument("package", required=False)
@click.option("--version", default=None, help="Optional package version.")
@click.option("--source", default="manual", help="Optional scan source path or ecosystem label.")
@click.option("-r", "--requirements", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Scan dependencies from a requirements.txt file.")
@click.option("--force", is_flag=True, help="Do not return a blocking exit code for threats.")
def check(package: str | None, version: str | None, source: str, requirements: Path | None, force: bool) -> None:
    """Perform a single package scan."""

    async def _run() -> int:
        console = Console()
        targets = resolve_check_targets(package, version, source, requirements)
        if not targets:
            if requirements is not None:
                console.print(f"[green]{requirements} - no dependencies to scan[/green]")
                return 0
            console.print("[red]No package or requirements file supplied.[/red]")
            return 2
        resolved_targets = await resolve_latest_versions(targets)
        scanner = SupplyScanScanner.with_default_detectors(explainer=build_explainer_from_env())
        reports = []
        has_invalid = False
        for resolved_target in resolved_targets:
            if resolved_target.warning is not None:
                console.print(f"[red]Error: {resolved_target.target.name} - {resolved_target.warning}[/red]")
                has_invalid = True
                continue
            report = await scanner.scan(resolved_target.target)
            reports.append(report)
            await ScanStore.default().save(report)
            render_scan_report(console, report)
        if has_invalid:
            return 1
        if not force and any(
            report.overall_severity in {Severity.CRITICAL, Severity.HIGH} for report in reports
        ):
            return 1
        return 0

    raise SystemExit(asyncio.run(_run()))


@main.command()
def init() -> None:
    """Install global pip and npm hooks."""

    console = Console()
    report = HookManager().install_hooks()
    render_hook_report(console, report)
    if report.has_errors:
        raise SystemExit(1)


@main.command("remove-hooks")
def remove_hooks() -> None:
    """Remove global pip and npm hooks."""

    console = Console()
    report = HookManager().remove_hooks()
    render_hook_report(console, report)
    if report.has_errors:
        raise SystemExit(1)


@main.command()
def history() -> None:
    """Print the last 20 scan records."""

    async def _run() -> None:
        console = Console()
        reports = await ScanStore.default().load_recent(20)
        render_history_table(console, reports)

    asyncio.run(_run())


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Dashboard bind host.")
@click.option("--port", default=8000, show_default=True, type=int, help="Dashboard bind port.")
def dashboard(host: str, port: int) -> None:
    """Launch the local FastAPI dashboard."""

    import uvicorn

    console = Console()
    console.print(f"[green]Starting SupplyScan dashboard at http://{host}:{port}[/green]")
    uvicorn.run("supplyscan.dashboard.app:app", host=host, port=port, reload=False)


def render_scan_report(console: Console, report: ScanReport) -> None:
    """Render a manual scan report."""

    package_label = f"{report.target.name} {report.target.version or ''}".strip()
    if report.clean:
        console.print(f"[green]{package_label} - clean[/green] ([dim]{report.duration_ms}ms[/dim])")
        return

    lines = [f"Severity: {report.overall_severity.value}", "", "Signals:"]
    for result in report.detector_results:
        for finding in result.findings:
            if result.name == "cve":
                metadata = cve_metadata_for_finding(finding, result.evidence)
                prefix, _, description = finding.partition(": ")
                cve_severity = metadata.get("severity", result.severity.value)
                fix = metadata.get("fix", "no fixed version published")
                lines.append(f"- {prefix} ({cve_severity}) - fix: {fix}")
                if description:
                    lines.append(f"  {description}")
            else:
                lines.append(f"- {format_finding_for_cli(result.name, finding)}")
            if result.name == "cve":
                advisory_url = evidence_url_for_finding(finding, result.evidence)
                if advisory_url:
                    lines.append(f"  {advisory_url}")
    ai_analysis_used = report.explanation is not None and not is_provider_failure_explanation(report.explanation)
    if report.explanation is not None:
        explanation = report.explanation.explanation
        recommended_action = report.explanation.recommended_action
        encoding = getattr(console, "encoding", "utf-8") or "utf-8"
        try:
            explanation.encode(encoding)
        except UnicodeEncodeError:
            explanation = explanation.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"').replace("‑", "-").replace("—", "-")
            explanation = explanation.encode(encoding, errors="replace").decode(encoding)
        try:
            recommended_action.encode(encoding)
        except UnicodeEncodeError:
            recommended_action = recommended_action.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"').replace("‑", "-").replace("—", "-")
            recommended_action = recommended_action.encode(encoding, errors="replace").decode(encoding)
        lines.extend(
            [
                "",
                f"AI Analysis: {'true' if ai_analysis_used else 'false'}",
                explanation,
                recommended_action,
            ]
        )
    else:
        lines.extend(["", "AI Analysis: false"])
    if report.overall_severity in {Severity.CRITICAL, Severity.HIGH}:
        lines.extend(["", "Install BLOCKED. Run with --force to override."])
    else:
        lines.extend(["", "Review recommended. Install is not automatically blocked."])
    console.print(
        Panel.fit(
            "\n".join(lines),
            title=f"THREAT DETECTED - {package_label}",
            border_style="red",
        )
    )


def resolve_check_targets(
    package: str | None,
    version: str | None,
    source: str,
    requirements: Path | None,
) -> list[ScanTarget]:
    """Resolve CLI check targets, honoring npm hook metadata when present."""

    npm_payload = os.getenv("SUPPLYSCAN_NPM_TARGET")
    if npm_payload:
        try:
            data = json.loads(npm_payload)
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            name_value = data.get("name")
            version_value = data.get("version")
            source_value = data.get("source")
            if isinstance(name_value, str) and name_value:
                package = name_value
            if isinstance(version_value, str) and version_value:
                version = version_value
            if isinstance(source_value, str) and source_value:
                source = source_value
    targets = []
    if requirements is not None:
        targets.extend(parse_requirements(requirements))
    if package is not None:
        parsed_name = package
        parsed_version = version

        # Handle NPM scoped package with version: e.g. @types/lodash@4.17.20
        if package.startswith("@"):
            parts = package[1:].split("@", 1)
            if len(parts) == 2:
                parsed_name = "@" + parts[0]
                parsed_version = parts[1]
        elif "@" in package:
            parsed_name, parsed_version = package.split("@", 1)
        elif "==" in package:
            parsed_name, parsed_version = package.split("==", 1)
        elif ">=" in package:
            parsed_name = package.split(">=", 1)[0]
            parsed_version = None
        elif "<=" in package:
            parsed_name = package.split("<=", 1)[0]
            parsed_version = None
        elif "~=" in package:
            parsed_name = package.split("~=", 1)[0]
            parsed_version = None
        elif "!=" in package:
            parsed_name = package.split("!=", 1)[0]
            parsed_version = None
        elif ">" in package:
            parsed_name = package.split(">", 1)[0]
            parsed_version = None
        elif "<" in package:
            parsed_name = package.split("<", 1)[0]
            parsed_version = None
        elif "=" in package:
            parsed_name, parsed_version = package.split("=", 1)

        parsed_name = parsed_name.strip()
        if parsed_version is not None:
            parsed_version = parsed_version.strip() or None

        if parsed_name == package:
            # No version separator was split out of the package name argument
            parsed_version = version

        normalized_source = source
        if normalized_source == "manual":
            normalized_source = "auto"
        targets.append(ScanTarget(name=parsed_name, version=parsed_version, source=normalized_source))
    return targets


def parse_requirements(path: Path) -> list[ScanTarget]:
    """Parse requirement specs into scan targets."""

    targets: list[ScanTarget] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        parsed = parse_requirement_spec(line)
        if parsed is not None:
            targets.append(parsed)
    return targets


def parse_requirement_spec(spec: str) -> ScanTarget | None:
    """Parse a single requirements.txt package spec."""

    cleaned = spec.strip()
    if not cleaned:
        return None
    if "==" in cleaned:
        name, version = cleaned.split("==", 1)
        return ScanTarget(name=name.strip(), version=version.strip() or None, source="requirements")
    if "@" in cleaned and cleaned.count("@") == 1:
        name = cleaned.split("@", 1)[0].strip()
        return ScanTarget(name=name, version=None, source="requirements") if name else None
    for operator in (">=", "<=", "~=", "!=", ">", "<"):
        if operator in cleaned:
            name = cleaned.split(operator, 1)[0].strip()
            return ScanTarget(name=name, version=None, source="requirements") if name else None
    return ScanTarget(name=cleaned, version=None, source="requirements")


def render_hook_report(console: Console, report: HookReport) -> None:
    """Render hook installation or removal details."""

    table = Table(title=f"SupplyScan hook {report.operation.value}")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Path")
    table.add_column("Detail")
    for action in report.actions:
        style = "green" if action.status == "changed" else "yellow" if action.status == "error" else "cyan"
        table.add_row(action.target, f"[{style}]{action.status}[/{style}]", action.path, action.detail)
    console.print(table)


def format_finding_for_cli(detector_name: str, finding: str) -> str:
    """Format a detector finding for human CLI output."""

    if detector_name != "cve":
        return finding
    return finding.replace(": ", " - ", 1)


def evidence_url_for_finding(finding: str, evidence_items: list[object]) -> str | None:
    """Return an advisory URL matching a CVE finding."""

    finding_id = finding.split(" ", 1)[0].split(":", 1)[0]
    for item in evidence_items:
        label = getattr(item, "label", "")
        value = getattr(item, "value", "")
        if label != finding_id or not isinstance(value, str):
            continue
        for part in value.split(";"):
            stripped = part.strip()
            if stripped.startswith("url="):
                return stripped.removeprefix("url=")
    return None


def cve_metadata_for_finding(finding: str, evidence_items: list[object]) -> dict[str, str]:
    """Return structured CVE metadata matching a finding."""

    finding_id = finding.split(" ", 1)[0].split(":", 1)[0]
    for item in evidence_items:
        label = getattr(item, "label", "")
        value = getattr(item, "value", "")
        if label != finding_id or not isinstance(value, str):
            continue
        metadata: dict[str, str] = {}
        for part in value.split(";"):
            if "=" not in part:
                continue
            key, raw = part.strip().split("=", 1)
            metadata[key] = raw
        return metadata
    return {}


def render_history_table(console: Console, reports: list[ScanReport]) -> None:
    """Render scan history as a Rich table."""

    table = Table(title=f"SupplyScan history ({default_store_path()})")
    table.add_column("Scanned At")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Severity")
    table.add_column("Clean")
    table.add_column("Duration")
    if not reports:
        console.print("[yellow]No scan history found.[/yellow]")
        return
    for report in reports:
        style = "green" if report.clean else "red" if report.overall_severity in {Severity.CRITICAL, Severity.HIGH} else "yellow"
        table.add_row(
            report.scanned_at.isoformat(),
            report.target.name,
            report.target.version or "",
            f"[{style}]{report.overall_severity.value}[/{style}]",
            "yes" if report.clean else "no",
            f"{report.duration_ms}ms",
        )
    console.print(table)


if __name__ == "__main__":
    main()
