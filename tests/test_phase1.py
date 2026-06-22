"""Phase 1 scanner model and orchestration tests."""

from __future__ import annotations

import pytest

from supplyscan.core.scanner import SupplyScanScanner
from supplyscan.models import DetectorResult, ScanTarget, Severity


class CleanDetector:
    """Detector fixture that always returns an informational result."""

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Return a clean detector result."""

        return DetectorResult(name="clean", severity=Severity.INFO, findings=[], evidence=[])


class HighDetector:
    """Detector fixture that always returns a high-severity result."""

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Return a high-severity detector result."""

        return DetectorResult(name="high", severity=Severity.HIGH, findings=["suspicious"], evidence=[])


@pytest.mark.asyncio
async def test_scanner_reports_clean_target() -> None:
    """Verify a scan with no findings is clean."""

    scanner = SupplyScanScanner(detectors=[CleanDetector()])
    report = await scanner.scan(ScanTarget(name="requests"))
    assert report.clean is True
    assert report.overall_severity == Severity.INFO


@pytest.mark.asyncio
async def test_scanner_reports_highest_detector_severity() -> None:
    """Verify a scan reports the highest detector severity."""

    scanner = SupplyScanScanner(detectors=[CleanDetector(), HighDetector()])
    report = await scanner.scan(ScanTarget(name="colourama", version="0.4.5"))
    assert report.clean is False
    assert report.overall_severity == Severity.HIGH


@pytest.mark.asyncio
async def test_local_feed_detector_critical_match() -> None:
    """Verify LocalFeedDetector flags known malicious packages in synced database."""

    import tempfile
    import json
    from pathlib import Path
    from supplyscan.detectors.local_feed import LocalFeedDetector

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cache_file = tmp_path / "feed.json"

        feed_data = {
            "schema_version": "1",
            "packages": [
                {
                    "ecosystem": "pypi",
                    "name": "malicious-test-pkg",
                    "all_versions": True,
                    "summary": "compromised package test",
                    "ids": ["MAL-2026-9999"],
                    "source": "depx",
                }
            ],
        }
        cache_file.write_text(json.dumps(feed_data), encoding="utf-8")

        detector = LocalFeedDetector(cache_dir=tmp_path)
        result = await detector.scan(ScanTarget(name="malicious-test-pkg", source="pypi"))

        assert result.severity == Severity.CRITICAL
        assert len(result.findings) == 1
        assert "MAL-2026-9999" in result.findings[0]


@pytest.mark.asyncio
async def test_maintainer_security_holding() -> None:
    """Verify MaintainerDetector flags packages in NPM security holding quarantine."""

    from supplyscan.detectors.maintainer import MaintainerDetector

    detector = MaintainerDetector()

    mock_payload = {
        "versions": {
            "1.0.0-security": {},
            "2.0.0-security": {},
        },
        "maintainers": [{"name": "compromised-user"}],
        "time": {
            "created": "2026-06-01T10:00:00Z",
            "1.0.0-security": "2026-06-01T10:00:00Z",
            "2.0.0-security": "2026-06-02T10:00:00Z",
        },
    }

    async def mock_get_json(url):
        return mock_payload

    async def mock_download_count(pkg, eco):
        return 100

    detector._get_json = mock_get_json
    detector._download_count = mock_download_count

    result = await detector.scan(ScanTarget(name="test-holding-pkg", source="npm"))
    assert result.severity == Severity.CRITICAL
    assert any("security holding" in finding.lower() for finding in result.findings)


def test_cli_resolve_check_targets_with_versions() -> None:
    """Verify resolve_check_targets parses inline version specifications."""

    from supplyscan.cli.main import resolve_check_targets

    targets = resolve_check_targets("lodash=4.17.20", None, "manual", None)
    assert len(targets) == 1
    assert targets[0].name == "lodash"
    assert targets[0].version == "4.17.20"
    assert targets[0].source == "auto"

    targets = resolve_check_targets("@types/lodash@4.17.20", None, "manual", None)
    assert len(targets) == 1
    assert targets[0].name == "@types/lodash"
    assert targets[0].version == "4.17.20"

    targets = resolve_check_targets("lodash>=4.17.20", None, "manual", None)
    assert len(targets) == 1
    assert targets[0].name == "lodash"
    assert targets[0].version is None


class FailingDetector:
    """Detector fixture that raises an exception during scanning."""

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Raise an exception to test error isolation in scanner."""

        raise RuntimeError("simulated detector failure")


@pytest.mark.asyncio
async def test_scanner_handles_failing_detector() -> None:
    """Verify that a detector exception is safely isolated and does not crash the scan."""

    scanner = SupplyScanScanner(detectors=[FailingDetector()])
    report = await scanner.scan(ScanTarget(name="requests"))
    assert report.clean is True
    assert len(report.detector_results) == 1
    result = report.detector_results[0]
    assert result.name == "FailingDetector"
    assert result.severity == Severity.INFO
    assert len(result.evidence) == 1
    assert result.evidence[0].label == "error"
    assert "simulated detector failure" in result.evidence[0].value


class FailingExplainer:
    """Explainer fixture that raises an exception during execution."""

    async def explain(self, target: ScanTarget, results: list[DetectorResult]) -> ThreatExplanation | None:
        raise RuntimeError("simulated explainer failure")


@pytest.mark.asyncio
async def test_scanner_handles_failing_explainer() -> None:
    """Verify that an explainer exception is safely isolated and does not crash the scan."""

    from supplyscan.models import ThreatExplanation
    scanner = SupplyScanScanner(detectors=[HighDetector()], explainer=FailingExplainer())
    report = await scanner.scan(ScanTarget(name="requests"))
    assert report.clean is False
    assert report.overall_severity == Severity.HIGH
    assert report.explanation is not None
    assert "simulated explainer failure" in report.explanation.recommended_action



