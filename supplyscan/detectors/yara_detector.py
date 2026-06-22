"""YARA rule detector."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import (
    ResultBuilder,
    collect_source_files,
    evidence,
    max_severity,
    resolve_source_path,
)
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity

try:
    import yara
except ImportError:
    yara = None


class YaraFinding(BaseModel):
    """YARA rule match finding."""

    model_config = ConfigDict(frozen=True)

    rule: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    severity: Severity
    tags: list[str] = Field(default_factory=list)


class YaraDetector:
    """Detect malware indicators with YARA rules."""

    def __init__(self, rule_paths: Iterable[Path] | None = None) -> None:
        """Create a YARA detector with bundled and optional rules."""

        default_rule = Path(__file__).resolve().parents[1] / "rules" / "malware.yar"
        self.rule_paths = tuple(rule_paths or (default_rule,))
        self.result_builder = ResultBuilder(detector_name="yara")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan source files with YARA rules."""

        root = resolve_source_path(target)
        if root is None:
            return self.result_builder.clean([evidence("scope", "no local source available")])
        if yara is None:
            return self.result_builder.clean([evidence("dependency", "yara-python is not installed")])

        rules = await self._compile_rules()
        if rules is None:
            return self.result_builder.clean([evidence("rules", "no YARA rules compiled")])

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO
        for source_file in await collect_source_files(root):
            matches = await asyncio.to_thread(rules.match, data=source_file.text.encode("utf-8", errors="ignore"))
            for match in matches:
                match_severity = severity_from_metadata(getattr(match, "meta", {}))
                severity = max_severity(severity, match_severity)
                findings.append(f"YARA rule {match.rule} matched {source_file.relative_path}")
                evidence_items.append(
                    evidence(
                        f"{source_file.relative_path}:{match.rule}",
                        f"tags={','.join(match.tags)}; severity={match_severity.value}",
                    )
                )

        return self.result_builder.build(findings, evidence_items, severity)

    async def _compile_rules(self) -> object | None:
        """Compile configured YARA rules."""

        existing = [path for path in self.rule_paths if path.exists()]
        if not existing:
            return None

        def _compile() -> object | None:
            """Compile YARA rules synchronously."""

            filepaths = {f"rule_{index}": path.as_posix() for index, path in enumerate(existing)}
            try:
                return yara.compile(filepaths=filepaths)
            except yara.Error:
                return None

        return await asyncio.to_thread(_compile)


def severity_from_metadata(metadata: object) -> Severity:
    """Resolve severity from YARA match metadata."""

    if not isinstance(metadata, dict):
        return Severity.MEDIUM
    raw = metadata.get("severity")
    if isinstance(raw, str):
        normalized = raw.upper()
        if normalized == "CRITICAL":
            return Severity.CRITICAL
        if normalized == "HIGH":
            return Severity.HIGH
        if normalized == "MEDIUM":
            return Severity.MEDIUM
        if normalized == "LOW":
            return Severity.LOW
        if normalized == "INFO":
            return Severity.INFO
    return Severity.MEDIUM
