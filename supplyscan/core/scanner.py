"""Scanner orchestrator for SupplyScan."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Protocol

from supplyscan.detectors import (
    AstDetector,
    CveDetector,
    EntropyDetector,
    LocalFeedDetector,
    MaintainerDetector,
    NetworkDetector,
    SemgrepDetector,
    TyposquatDetector,
    YaraDetector,
)
from supplyscan.models import DetectorResult, EvidenceItem, ScanReport, ScanTarget, Severity, ThreatExplanation


class Detector(Protocol):
    """Protocol implemented by all detectors."""

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan a package target and return a normalized result."""


class Explainer(Protocol):
    """Protocol implemented by AI explainers."""

    async def explain(self, target: ScanTarget, results: list[DetectorResult]) -> ThreatExplanation | None:
        """Produce a human explanation for a threat, if any."""


@dataclass(slots=True)
class SupplyScanScanner:
    """Coordinate all detectors and produce a report."""

    detectors: list[Detector]
    explainer: Explainer | None = None

    @classmethod
    def with_default_detectors(cls, explainer: Explainer | None = None) -> "SupplyScanScanner":
        """Create a scanner preloaded with the standard Phase 2 detector stack."""

        return cls(
            detectors=[
                CveDetector(),
                EntropyDetector(),
                TyposquatDetector(),
                AstDetector(),
                NetworkDetector(),
                YaraDetector(),
                SemgrepDetector(),
                MaintainerDetector(),
                LocalFeedDetector(),
            ],
            explainer=explainer,
        )

    @classmethod
    def with_mode_detectors(cls, mode: str = "all", explainer: Explainer | None = None) -> "SupplyScanScanner":
        """Create a scanner preloaded with detectors filtered by the scan mode."""

        all_detectors = [
            CveDetector(),
            EntropyDetector(),
            TyposquatDetector(),
            AstDetector(),
            NetworkDetector(),
            YaraDetector(),
            SemgrepDetector(),
            MaintainerDetector(),
            LocalFeedDetector(),
        ]
        if mode == "known":
            detectors = [d for d in all_detectors if isinstance(d, (CveDetector, LocalFeedDetector))]
        elif mode == "unknown":
            detectors = [d for d in all_detectors if not isinstance(d, (CveDetector, LocalFeedDetector))]
        else:
            detectors = all_detectors

        return cls(detectors=detectors, explainer=explainer)


    async def scan(self, target: ScanTarget) -> ScanReport:
        """Run the configured detectors against a target package.

        Detectors are I/O-bound (registry/advisory lookups) and independent, so
        they run concurrently. A detector that raises is isolated into a
        non-fatal error result instead of failing the whole scan, which keeps
        the pipeline resilient during live use.
        """

        started = perf_counter()
        gathered = await asyncio.gather(
            *(detector.scan(target) for detector in self.detectors),
            return_exceptions=True,
        )
        results: list[DetectorResult] = [
            self._normalize_result(detector, outcome)
            for detector, outcome in zip(self.detectors, gathered)
        ]

        explanation = None
        overall_severity = self._resolve_severity(results)
        if any(result.has_findings for result in results) and self.explainer is not None:
            try:
                explanation = await self.explainer.explain(target, results)
                if explanation is not None:
                    overall_severity = self._max_severity(overall_severity, explanation.severity)
            except Exception as exc:
                import logging
                logging.getLogger("supplyscan").error(f"AI explainer failed: {exc}", exc_info=True)
                from supplyscan.ai.claude_explainer import local_failure_explanation
                explanation = local_failure_explanation(
                    target,
                    [r for r in results if r.has_findings],
                    f"Explainer error: {exc}"
                )

        duration_ms = int((perf_counter() - started) * 1000)
        return ScanReport(
            target=target,
            scanned_at=datetime.now(timezone.utc),
            duration_ms=duration_ms,
            clean=overall_severity == Severity.INFO,
            overall_severity=overall_severity,
            detector_results=results,
            explanation=explanation,
            metadata={},
        )

    @staticmethod
    def _normalize_result(detector: Detector, outcome: DetectorResult | BaseException) -> DetectorResult:
        """Convert a gathered detector outcome into a safe DetectorResult."""

        if isinstance(outcome, DetectorResult):
            return outcome
        name = getattr(type(detector), "__name__", "detector")
        return DetectorResult(
            name=name,
            severity=Severity.INFO,
            findings=[],
            evidence=[EvidenceItem(label="error", value=str(outcome) or "detector failed")],
        )

    @staticmethod
    def _resolve_severity(results: list[DetectorResult]) -> Severity:
        """Derive the highest severity from detector outputs."""

        highest = Severity.INFO
        for result in results:
            highest = SupplyScanScanner._max_severity(highest, result.severity)
        return highest

    @staticmethod
    def _max_severity(left: Severity, right: Severity) -> Severity:
        """Return the more severe of two severity values."""

        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return left if order[left] >= order[right] else right
