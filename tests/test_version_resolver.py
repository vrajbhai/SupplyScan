"""Latest-version resolver tests."""

from __future__ import annotations

import pytest

from supplyscan.core.version_resolver import (
    infer_registry,
    latest_version_from_npm_payload,
    latest_version_from_pypi_payload,
    resolve_latest_version,
)
from supplyscan.models import ScanTarget


def test_extracts_npm_latest_dist_tag() -> None:
    """Verify npm latest version extraction."""

    payload = {"dist-tags": {"latest": "4.18.2"}}
    assert latest_version_from_npm_payload(payload) == "4.18.2"


def test_extracts_pypi_info_version() -> None:
    """Verify PyPI latest version extraction."""

    payload = {"info": {"version": "2.32.5"}}
    assert latest_version_from_pypi_payload(payload) == "2.32.5"


def test_infers_common_npm_package() -> None:
    """Verify common JavaScript packages default to npm."""

    assert infer_registry(ScanTarget(name="express", source="auto")) == "npm"


def test_infers_requirements_as_pypi() -> None:
    """Verify requirements entries resolve against PyPI."""

    assert infer_registry(ScanTarget(name="requests", source="requirements")) == "pypi"


@pytest.mark.asyncio
async def test_resolve_latest_version_explicit_version_maps_source() -> None:
    """Verify that resolving a target with explicit version maps its source registry correctly."""
    target = ScanTarget(name="lodash", version="4.17.21", source="auto")
    result = await resolve_latest_version(target)
    assert result.target.source == "npm"
    assert result.registry == "npm"


@pytest.mark.asyncio
async def test_resolve_latest_version_demo_fixtures() -> None:
    """Verify that demo packages auto-resolve to local fixture source directories."""
    target = ScanTarget(name="colourama", source="auto")
    result = await resolve_latest_version(target)
    assert result.resolved is True
    assert "tests" in result.target.source
    assert "colourama_045" in result.target.source
    assert result.target.version == "0.4.5"
    assert result.registry == "pypi"
    assert result.exists_in_both is True


@pytest.mark.asyncio
async def test_resolve_latest_version_non_existent_package() -> None:
    """Verify that resolving a non-existent package sets a descriptive warning."""
    target = ScanTarget(name="this-package-does-not-exist-anywhere-in-the-world-12345", source="auto")
    result = await resolve_latest_version(target)
    assert result.resolved is False
    assert result.warning is not None
    assert "does not exist on npm or PyPI registries" in result.warning

