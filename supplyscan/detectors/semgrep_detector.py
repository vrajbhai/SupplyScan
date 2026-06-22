"""Semgrep detector for supply-chain rules."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import ResultBuilder, evidence, max_severity, resolve_source_path
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


class SemgrepFinding(BaseModel):
    """Semgrep finding normalized for SupplyScan."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    message: str = Field(min_length=1)
    severity: Severity


class SemgrepDetector:
    """Run Semgrep supply-chain rules against local source."""

    def __init__(self, executable: str = "semgrep", config_path: Path | None = None) -> None:
        """Create a Semgrep detector."""

        default_config = Path(__file__).resolve().parents[1] / "rules" / "semgrep" / "supply_chain.yml"
        self.executable = executable
        self.config_path = config_path or default_config
        self.result_builder = ResultBuilder(detector_name="semgrep")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Run Semgrep and normalize its JSON output."""

        root = resolve_source_path(target)
        if root is None:
            return self.result_builder.clean([evidence("scope", "no local source available")])
        if not self.config_path.exists():
            return self.result_builder.clean([evidence("rules", "Semgrep config not found")])

        payload, command_evidence = await self._run_semgrep(root)
        if payload is None:
            return self.result_builder.clean(command_evidence)

        parsed_findings = parse_semgrep_results(payload)
        findings: list[str] = []
        evidence_items: list[EvidenceItem] = list(command_evidence)
        severity = Severity.INFO
        for item in parsed_findings:
            severity = max_severity(severity, item.severity)
            findings.append(f"Semgrep {item.rule_id} in {item.path} line {item.line}: {item.message}")
            evidence_items.append(
                evidence(
                    f"{item.path}:{item.line}",
                    f"rule={item.rule_id}; severity={item.severity.value}",
                )
            )

        return self.result_builder.build(findings, evidence_items, severity)

    async def _run_semgrep(self, root: Path) -> tuple[dict[str, Any] | None, list[EvidenceItem]]:
        """Execute Semgrep and return parsed JSON payload with command evidence."""

        try:
            process = await asyncio.create_subprocess_exec(
                self.executable,
                "--json",
                "--quiet",
                "--config",
                self.config_path.as_posix(),
                root.as_posix(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return None, [evidence("dependency", "semgrep executable not found")]

        stdout, stderr = await process.communicate()
        if process.returncode not in {0, 1}:
            message = stderr.decode("utf-8", errors="replace").strip()
            return None, [evidence("semgrep-error", message[:500] or f"exit={process.returncode}")]
        try:
            payload = json.loads(stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            return None, [evidence("semgrep-error", f"invalid JSON output: {exc}")]
        return payload if isinstance(payload, dict) else None, []


def parse_semgrep_results(payload: dict[str, Any]) -> list[SemgrepFinding]:
    """Parse Semgrep JSON results."""

    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        return []
    findings: list[SemgrepFinding] = []
    for raw in raw_results:
        if not isinstance(raw, dict):
            continue
        extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}
        start = raw.get("start") if isinstance(raw.get("start"), dict) else {}
        severity = severity_from_semgrep(extra.get("severity"))
        rule_id = str(raw.get("check_id") or "unknown")
        path = str(raw.get("path") or "unknown")
        line_value = start.get("line") if isinstance(start, dict) else 1
        if not isinstance(line_value, int):
            line_value = 1
        line = line_value if line_value >= 1 else 1
        message = str(extra.get("message") or rule_id)
        findings.append(
            SemgrepFinding(
                rule_id=rule_id,
                path=path,
                line=line,
                message=message,
                severity=severity,
            )
        )
    return findings


def severity_from_semgrep(value: object) -> Severity:
    """Map Semgrep severities to SupplyScan severity."""

    if not isinstance(value, str):
        return Severity.MEDIUM
    normalized = value.upper()
    if normalized == "ERROR":
        return Severity.HIGH
    if normalized == "WARNING":
        return Severity.MEDIUM
    if normalized == "INFO":
        return Severity.LOW
    return Severity.MEDIUM
