"""Entropy and encoded-payload detector."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import (
    ResultBuilder,
    collect_source_files,
    evidence,
    max_severity,
    resolve_source_path,
)
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


class StringLiteralHit(BaseModel):
    """Encoded or high-entropy string literal finding."""

    model_config = ConfigDict(frozen=True)

    kind: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    score: float | None = None
    preview: str = Field(min_length=1)


class EntropyDetector:
    """Detect obfuscated strings, base64 payloads, and long hex payloads."""

    def __init__(self, entropy_threshold: float = 4.5, min_literal_length: int = 20) -> None:
        """Create an entropy detector with tunable thresholds."""

        self.entropy_threshold = entropy_threshold
        self.min_literal_length = min_literal_length
        self.result_builder = ResultBuilder(detector_name="entropy")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan source files for suspicious string literal obfuscation."""

        root = resolve_source_path(target)
        if root is None:
            return self.result_builder.clean([evidence("scope", "no local source available")])

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO
        for source_file in await collect_source_files(root):
            hits = self._scan_text(source_file.text, source_file.relative_path)
            for hit in hits:
                severity = max_severity(severity, self._severity_for_hit(hit))
                findings.append(self._finding_for_hit(hit))
                evidence_items.append(
                    evidence(
                        f"{hit.relative_path}:{hit.line_number}",
                        self._evidence_value(hit),
                    )
                )

        return self.result_builder.build(findings, evidence_items, severity)

    def _scan_text(self, text: str, relative_path: str) -> list[StringLiteralHit]:
        """Scan text for encoded and high-entropy literals."""

        hits: list[StringLiteralHit] = []
        for line_number, literal in self._iter_string_like_tokens(text):
            compact = literal.strip()
            if len(compact) < self.min_literal_length:
                continue
            entropy = calculate_shannon_entropy(compact)
            if entropy > self.entropy_threshold:
                hits.append(
                    StringLiteralHit(
                        kind="high-entropy string",
                        relative_path=relative_path,
                        line_number=line_number,
                        score=entropy,
                        preview=preview(compact),
                    )
                )
            if is_probable_base64_payload(compact):
                hits.append(
                    StringLiteralHit(
                        kind="base64 payload",
                        relative_path=relative_path,
                        line_number=line_number,
                        score=None,
                        preview=preview(compact),
                    )
                )
            if is_long_hex_payload(compact):
                hits.append(
                    StringLiteralHit(
                        kind="hex encoded payload",
                        relative_path=relative_path,
                        line_number=line_number,
                        score=None,
                        preview=preview(compact),
                    )
                )
        return hits

    def _iter_string_like_tokens(self, text: str) -> list[tuple[int, str]]:
        """Extract quoted strings and unquoted encoded blobs with line numbers."""

        tokens: list[tuple[int, str]] = []
        string_pattern = re.compile(r"""(?P<quote>['"])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)""")
        blob_pattern = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9A-Fa-f]{50,})\b")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in string_pattern.finditer(line):
                tokens.append((line_number, match.group("value")))
            for match in blob_pattern.finditer(line):
                tokens.append((line_number, match.group(0)))
        return tokens

    def _severity_for_hit(self, hit: StringLiteralHit) -> Severity:
        """Resolve severity for a specific obfuscation hit."""

        if hit.kind in {"base64 payload", "hex encoded payload"}:
            return Severity.HIGH
        if hit.score is not None and hit.score >= 5.5:
            return Severity.HIGH
        return Severity.MEDIUM

    def _finding_for_hit(self, hit: StringLiteralHit) -> str:
        """Render a finding sentence for a hit."""

        if hit.score is None:
            return f"{hit.kind} in {hit.relative_path} line {hit.line_number}"
        return (
            f"{hit.kind} entropy {hit.score:.2f} in "
            f"{hit.relative_path} line {hit.line_number}"
        )

    def _evidence_value(self, hit: StringLiteralHit) -> str:
        """Render evidence text for a hit."""

        if hit.score is None:
            return f"{hit.kind}: {hit.preview}"
        return f"{hit.kind}: entropy={hit.score:.2f}; preview={hit.preview}"


def calculate_shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy for a string."""

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_probable_base64_payload(value: str) -> bool:
    """Return whether a string looks like a decodable base64 payload."""

    compact = re.sub(r"\s+", "", value)
    if len(compact) < 40 or len(compact) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return False
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(decoded) < 24:
        return False
    printable = sum(32 <= byte <= 126 or byte in {9, 10, 13} for byte in decoded)
    return printable / len(decoded) > 0.65 or calculate_shannon_entropy(decoded.hex()) > 3.5


def is_long_hex_payload(value: str) -> bool:
    """Return whether a string contains a long hex-encoded payload."""

    compact = value.replace("\\x", "")
    return len(compact) > 50 and len(compact) % 2 == 0 and bool(re.fullmatch(r"[0-9A-Fa-f]+", compact))


def preview(value: str, limit: int = 80) -> str:
    """Return a safe one-line preview of a suspicious string."""

    normalized = value.replace("\n", "\\n").replace("\r", "\\r")
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."
