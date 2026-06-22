"""End-to-end detection tests against the bundled malicious package fixtures.

These tests prove the behavioral detector stack catches real supply-chain
attack patterns (typosquats, install-time exfiltration, obfuscated payloads)
that legacy CVE-only scanners miss. They run fully offline by scanning the
local fixture source trees with the deterministic local-source detectors, so
they are safe for CI and reproducible during a live demo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from supplyscan.core.scanner import SupplyScanScanner
from supplyscan.detectors import (
    AstDetector,
    EntropyDetector,
    NetworkDetector,
    YaraDetector,
)
from supplyscan.models import ScanTarget, Severity


FIXTURE_ROOT = Path(__file__).parent / "malicious"
BLOCKING_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


def local_source_scanner() -> SupplyScanScanner:
    """Build a scanner using only deterministic, offline local-source detectors.

    YARA degrades gracefully to a clean result when yara-python is missing, so
    including it never breaks CI but strengthens detection when available.
    """

    return SupplyScanScanner(
        detectors=[
            EntropyDetector(),
            AstDetector(),
            NetworkDetector(),
            YaraDetector(),
        ]
    )


def detector_names_with_findings(report) -> set[str]:
    """Return the set of detector names that produced a real finding."""

    return {result.name for result in report.detector_results if result.has_findings}


@pytest.mark.asyncio
async def test_colourama_typosquat_is_blocked() -> None:
    """colourama 0.4.5 (colorama typosquat) must be flagged as a blocking threat."""

    target = ScanTarget(
        name="colourama",
        version="0.4.5",
        source=str(FIXTURE_ROOT / "colourama_045"),
    )
    report = await local_source_scanner().scan(target)

    assert report.clean is False
    assert report.overall_severity in BLOCKING_SEVERITIES
    fired = detector_names_with_findings(report)
    # Install-time network exfiltration and the base64 reverse-shell payload
    # are the signals npm/pip audit cannot see.
    assert "network" in fired
    assert "entropy" in fired


@pytest.mark.asyncio
async def test_event_stream_postinstall_payload_is_blocked() -> None:
    """event-stream 3.3.6 obfuscated postinstall payload must be flagged."""

    target = ScanTarget(
        name="event-stream",
        version="3.3.6",
        source=str(FIXTURE_ROOT / "event_stream_336"),
    )
    report = await local_source_scanner().scan(target)

    assert report.clean is False
    assert report.overall_severity in BLOCKING_SEVERITIES
    # The base64-encoded eval payload in index.js is the key signal.
    assert "entropy" in detector_names_with_findings(report)


@pytest.mark.asyncio
async def test_fake_numpy_install_exfiltration_is_blocked() -> None:
    """fake_numpy_fast install-time env exfiltration must be flagged."""

    target = ScanTarget(
        name="fake_numpy_fast",
        version="1.0.0",
        source=str(FIXTURE_ROOT / "fake_numpy_fast"),
    )
    report = await local_source_scanner().scan(target)

    assert report.clean is False
    assert report.overall_severity in BLOCKING_SEVERITIES
    assert "network" in detector_names_with_findings(report)


@pytest.mark.asyncio
async def test_benign_package_passes_clean(tmp_path: Path) -> None:
    """A healthy package with no suspicious behavior must scan clean.

    This guards against false positives, which is the failure mode that makes
    security tooling get disabled in practice.
    """

    package_dir = tmp_path / "tidy_utils"
    package_dir.mkdir()
    (package_dir / "setup.py").write_text(
        "from setuptools import setup\n\n"
        "setup(name='tidy_utils', version='1.0.0', py_modules=['tidy_utils'])\n",
        encoding="utf-8",
    )
    (package_dir / "tidy_utils.py").write_text(
        '"""A small, well-behaved helper module."""\n\n\n'
        "def add(left, right):\n"
        '    """Return the sum of two numbers."""\n\n'
        "    return left + right\n",
        encoding="utf-8",
    )

    target = ScanTarget(name="tidy_utils", version="1.0.0", source=str(package_dir))
    report = await local_source_scanner().scan(target)

    assert report.clean is True
    assert report.overall_severity == Severity.INFO
