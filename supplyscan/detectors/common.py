"""Shared detector utilities."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


TEXT_SUFFIXES = frozenset(
    {
        ".cjs",
        ".js",
        ".json",
        ".jsx",
        ".mjs",
        ".py",
        ".pyi",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
)

IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "dist",
        "node_modules",
        "venv",
    }
)


class SourceFile(BaseModel):
    """Text file loaded from a scan target source tree."""

    model_config = ConfigDict(frozen=True)

    path: Path
    relative_path: str = Field(min_length=1)
    text: str


class ResultBuilder(BaseModel):
    """Accumulate detector findings into a normalized result."""

    model_config = ConfigDict(frozen=True)

    detector_name: str = Field(min_length=1)

    def clean(self, evidence: list[EvidenceItem] | None = None) -> DetectorResult:
        """Return an informational result with no findings."""

        return DetectorResult(
            name=self.detector_name,
            severity=Severity.INFO,
            findings=[],
            evidence=evidence or [],
        )

    def build(self, findings: list[str], evidence: list[EvidenceItem], severity: Severity) -> DetectorResult:
        """Return a detector result using the supplied findings and severity."""

        if not findings:
            return self.clean(evidence)
        return DetectorResult(
            name=self.detector_name,
            severity=severity,
            findings=findings,
            evidence=evidence,
        )


def evidence(label: str, value: str) -> EvidenceItem:
    """Create a structured evidence item."""

    return EvidenceItem(label=label, value=value)


def max_severity(current: Severity, candidate: Severity) -> Severity:
    """Return the more severe of two severity values."""

    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return current if order[current] >= order[candidate] else candidate


def resolve_source_path(target: ScanTarget) -> Path | None:
    """Resolve the local source path carried by a scan target."""

    if target.source is None:
        return None
    path = Path(target.source).expanduser()
    if not path.exists():
        return None
    return path.resolve()


async def read_text_file(path: Path, max_bytes: int = 1_000_000) -> str | None:
    """Read a text file asynchronously, returning None for binary or oversized files."""

    def _read() -> str | None:
        """Read a bounded amount of text from disk."""

        if not path.is_file() or path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    return await asyncio.to_thread(_read)


async def collect_source_files(
    root: Path,
    suffixes: Iterable[str] = TEXT_SUFFIXES,
    max_bytes: int = 1_000_000,
) -> list[SourceFile]:
    """Collect readable source files beneath a root directory."""

    suffix_set = frozenset(suffixes)

    def _paths() -> list[Path]:
        """Enumerate candidate text file paths."""

        if root.is_file():
            return [root] if root.suffix.lower() in suffix_set else []
        paths: list[Path] = []
        for path in root.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix.lower() in suffix_set:
                paths.append(path)
        return paths

    files: list[SourceFile] = []
    for path in await asyncio.to_thread(_paths):
        text = await read_text_file(path, max_bytes=max_bytes)
        if text is None:
            continue
        relative_path = path.name if root.is_file() else path.relative_to(root).as_posix()
        files.append(SourceFile(path=path, relative_path=relative_path, text=text))
    return files


def iter_lines(text: str) -> Iterable[tuple[int, str]]:
    """Yield one-based line numbers with line text."""

    for line_number, line in enumerate(text.splitlines(), start=1):
        yield line_number, line


def is_install_context(relative_path: str) -> bool:
    """Return whether a file participates directly in installation."""

    normalized = relative_path.replace("\\", "/").lower()
    basename = normalized.rsplit("/", maxsplit=1)[-1]
    return (
        basename in {"setup.py", "pyproject.toml", "package.json", "__init__.py"}
        or "/scripts/" in normalized
        or "/postinstall" in normalized
        or "/preinstall" in normalized
        or "/install" in normalized
    )
