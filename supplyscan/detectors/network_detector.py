"""Install-time network activity detector."""

from __future__ import annotations

import asyncio
import json
import re

from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import (
    ResultBuilder,
    collect_source_files,
    evidence,
    is_install_context,
    max_severity,
    resolve_source_path,
)
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


NETWORK_PATTERNS = (
    "socket",
    "urllib",
    "requests.",
    "httpx.",
    "aiohttp",
    "curl ",
    "wget ",
    "fetch(",
    "dns.lookup",
    "require('dns')",
    'require("dns")',
    "net.connect",
    "http.request",
    "https.request",
)

INSTALL_SCRIPT_NAMES = frozenset({"preinstall", "install", "postinstall", "prepare"})


class NetworkFinding(BaseModel):
    """Network-call finding in a package file or script."""

    model_config = ConfigDict(frozen=True)

    relative_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    pattern: str = Field(min_length=1)
    install_context: bool


class NetworkDetector:
    """Detect unexpected network calls in package install contexts."""

    def __init__(self, oxc_executable: str = "oxc") -> None:
        """Create a network detector."""

        self.oxc_executable = oxc_executable
        self.result_builder = ResultBuilder(detector_name="network")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan local package source for install-time network activity."""

        root = resolve_source_path(target)
        if root is None:
            return self.result_builder.clean([evidence("scope", "no local source available")])

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO
        for source_file in await collect_source_files(root):
            file_findings = self._scan_text(source_file.relative_path, source_file.text)
            if source_file.relative_path.lower().endswith("package.json"):
                file_findings.extend(self._scan_package_json(source_file.relative_path, source_file.text))
            if source_file.path.suffix.lower() in {".js", ".cjs", ".mjs", ".ts"}:
                evidence_items.extend(await self._run_oxc_parse_check(source_file.path.as_posix()))
            for item in file_findings:
                item_severity = Severity.HIGH if item.install_context else Severity.MEDIUM
                severity = max_severity(severity, item_severity)
                findings.append(
                    f"Network call '{item.pattern}' in {item.relative_path} line {item.line_number}"
                )
                evidence_items.append(
                    evidence(
                        f"{item.relative_path}:{item.line_number}",
                        f"install_context={item.install_context}; pattern={item.pattern}",
                    )
                )

        return self.result_builder.build(findings, evidence_items, severity)

    def _scan_text(self, relative_path: str, text: str) -> list[NetworkFinding]:
        """Scan raw text for network-capable APIs and commands."""

        findings: list[NetworkFinding] = []
        install_context = is_install_context(relative_path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            lower_line = line.lower()
            for pattern in NETWORK_PATTERNS:
                if pattern.lower() in lower_line:
                    findings.append(
                        NetworkFinding(
                            relative_path=relative_path,
                            line_number=line_number,
                            pattern=pattern,
                            install_context=install_context,
                        )
                    )
        return findings

    def _scan_package_json(self, relative_path: str, text: str) -> list[NetworkFinding]:
        """Scan npm lifecycle scripts in package.json."""

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []
        scripts = payload.get("scripts")
        if not isinstance(scripts, dict):
            return []

        findings: list[NetworkFinding] = []
        for script_name, script_value in scripts.items():
            if not isinstance(script_name, str) or not isinstance(script_value, str):
                continue
            if script_name not in INSTALL_SCRIPT_NAMES:
                continue
            for pattern in NETWORK_PATTERNS:
                if re.search(re.escape(pattern.strip()), script_value, flags=re.IGNORECASE):
                    findings.append(
                        NetworkFinding(
                            relative_path=relative_path,
                            line_number=1,
                            pattern=f"script:{script_name}:{pattern}",
                            install_context=True,
                        )
                    )
        return findings

    async def _run_oxc_parse_check(self, path: str) -> list[EvidenceItem]:
        """Use Oxc via subprocess when available to verify JavaScript parseability."""

        try:
            process = await asyncio.create_subprocess_exec(
                self.oxc_executable,
                "parser",
                path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return []
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            return [evidence("oxc", f"parsed {path}")]
        message = (stderr or stdout).decode("utf-8", errors="replace").strip()
        return [evidence("oxc", f"parse issue in {path}: {message[:200]}")]
