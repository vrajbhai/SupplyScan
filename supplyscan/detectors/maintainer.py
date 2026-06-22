"""Maintainer anomaly detector."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import (
    ResultBuilder,
    collect_source_files,
    evidence,
    max_severity,
    resolve_source_path,
)
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


class MaintainerSnapshot(BaseModel):
    """Registry snapshot with ownership and release history."""

    model_config = ConfigDict(frozen=True)

    package: str = Field(min_length=1)
    ecosystem: str = Field(min_length=1)
    maintainers: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    last_release_at: datetime | None = None
    previous_release_at: datetime | None = None
    release_count: int = 0
    downloads: int | None = None
    single_maintainer: bool = False
    security_holding: bool = False


class MaintainerFinding(BaseModel):
    """Maintainer anomaly finding."""

    model_config = ConfigDict(frozen=True)

    label: str = Field(min_length=1)
    severity: Severity
    evidence_text: str = Field(min_length=1)


class MaintainerDetector:
    """Detect suspicious maintainer and release history changes."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        """Create a maintainer detector."""

        self.http_client = http_client
        self.result_builder = ResultBuilder(detector_name="maintainer")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan maintainer and release metadata."""

        ecosystem = infer_ecosystem(target)
        snapshot = await self._load_snapshot(target, ecosystem)
        if snapshot is None:
            return self.result_builder.clean([evidence("scope", "no maintainer metadata available")])

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO
        generated = self._evaluate(snapshot)
        for finding in generated:
            findings.append(finding.label)
            evidence_items.append(evidence("maintainer", finding.evidence_text))
            severity = max_severity(severity, finding.severity)

        return self.result_builder.build(findings, evidence_items, severity)

    async def _load_snapshot(self, target: ScanTarget, ecosystem: str) -> MaintainerSnapshot | None:
        """Load maintainer snapshot from local files and registries."""

        local_snapshot = await self._local_snapshot(target, ecosystem)
        remote_snapshot = await self._registry_snapshot(target.name, ecosystem)
        if local_snapshot is None and remote_snapshot is None:
            return None
        if local_snapshot is None:
            return remote_snapshot
        if remote_snapshot is None:
            return local_snapshot
        return local_snapshot.model_copy(
            update={
                "created_at": remote_snapshot.created_at or local_snapshot.created_at,
                "last_release_at": remote_snapshot.last_release_at or local_snapshot.last_release_at,
                "previous_release_at": (
                    remote_snapshot.previous_release_at or local_snapshot.previous_release_at
                ),
                "release_count": max(local_snapshot.release_count, remote_snapshot.release_count),
                "downloads": remote_snapshot.downloads or local_snapshot.downloads,
                "maintainers": remote_snapshot.maintainers or local_snapshot.maintainers,
                "single_maintainer": remote_snapshot.single_maintainer or local_snapshot.single_maintainer,
                "security_holding": remote_snapshot.security_holding,
            }
        )

    async def _local_snapshot(self, target: ScanTarget, ecosystem: str) -> MaintainerSnapshot | None:
        """Infer maintainer metadata from local package files."""

        root = resolve_source_path(target)
        if root is None:
            return None
        package_name = target.name
        maintainers: set[str] = set()
        release_count = 0
        last_release_at: datetime | None = None
        created_at: datetime | None = None
        for source_file in await collect_source_files(root, suffixes={".json", ".toml", ".py"}):
            normalized = source_file.relative_path.replace("\\", "/").lower()
            if normalized.endswith("package.json"):
                package_name, maintainers = parse_package_json_metadata(source_file.text, package_name, maintainers)
            elif normalized.endswith("pyproject.toml"):
                package_name, maintainers = parse_pyproject_metadata(source_file.text, package_name, maintainers)
            elif normalized.endswith("setup.py"):
                package_name = parse_setup_py_name(source_file.text) or package_name
                if "maintainer" in source_file.text.lower():
                    maintainers.add("local-maintainer")
            release_count += 1
            stat_time = datetime.fromtimestamp(source_file.path.stat().st_mtime, tz=timezone.utc)
            last_release_at = max(last_release_at, stat_time) if last_release_at else stat_time
            created_at = min(created_at, stat_time) if created_at else stat_time
        if not maintainers:
            maintainers.add("unknown")
        return MaintainerSnapshot(
            package=package_name,
            ecosystem=ecosystem,
            maintainers=sorted(maintainers),
            created_at=created_at,
            last_release_at=last_release_at,
            release_count=release_count,
            downloads=None,
            previous_release_at=None,
            single_maintainer=len(maintainers) == 1,
        )

    async def _registry_snapshot(self, package_name: str, ecosystem: str) -> MaintainerSnapshot | None:
        """Fetch registry metadata for a package."""

        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{package_name}"
            payload, downloads = await asyncio.gather(
                self._get_json(url),
                self._download_count(package_name, ecosystem),
            )
            if payload is None:
                return None
            maintainers = parse_npm_maintainers(payload)
            created_at = parse_datetime_from_payload(payload, ("time", "created"))
            release_timestamps = parse_npm_release_timestamps(payload)
            last_release_at = release_timestamps[-1] if release_timestamps else None
            previous_release_at = release_timestamps[-2] if len(release_timestamps) > 1 else None
            release_count = count_npm_versions(payload)

            versions = payload.get("versions")
            security_holding = False
            if isinstance(versions, dict) and versions:
                security_holding = all(
                    v.lower().strip().endswith("-security") for v in versions.keys()
                )

            return MaintainerSnapshot(
                package=package_name,
                ecosystem=ecosystem,
                maintainers=maintainers or ["unknown"],
                created_at=created_at,
                last_release_at=last_release_at,
                previous_release_at=previous_release_at,
                release_count=release_count,
                downloads=downloads,
                single_maintainer=len(maintainers) == 1,
                security_holding=security_holding,
            )

        url = f"https://pypi.org/pypi/{package_name}/json"
        payload, downloads = await asyncio.gather(
            self._get_json(url),
            self._download_count(package_name, ecosystem),
        )
        if payload is None:
            return None
        maintainers = parse_pypi_maintainers(payload)
        release_timestamps = parse_pypi_release_timestamps(payload)
        created_at = release_timestamps[0] if release_timestamps else None
        last_release_at = release_timestamps[-1] if release_timestamps else None
        previous_release_at = release_timestamps[-2] if len(release_timestamps) > 1 else None
        release_count = count_pypi_versions(payload)
        return MaintainerSnapshot(
            package=package_name,
            ecosystem=ecosystem,
            maintainers=maintainers or ["unknown"],
            created_at=created_at,
            last_release_at=last_release_at,
            previous_release_at=previous_release_at,
            release_count=release_count,
            downloads=downloads,
            single_maintainer=len(maintainers) == 1,
        )

    async def _get_json(self, url: str) -> dict[str, Any] | None:
        """Fetch JSON from a registry URL."""

        try:
            if self.http_client is not None:
                response = await self.http_client.get(url, timeout=5.0)
            else:
                async with httpx.AsyncClient(follow_redirects=True) as client:
                    response = await client.get(url, timeout=5.0)
            if response.status_code >= 400:
                return None
            payload = response.json()
            return payload if isinstance(payload, dict) else None
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

    async def _download_count(self, package_name: str, ecosystem: str) -> int | None:
        """Fetch last-month download count from npm or PyPI stats APIs."""

        if ecosystem == "npm":
            url = f"https://api.npmjs.org/downloads/point/last-month/{package_name}"
            payload = await self._get_json(url)
            if payload is None:
                return None
            downloads = payload.get("downloads")
            return downloads if isinstance(downloads, int) else None

        url = f"https://pypistats.org/api/packages/{package_name}/recent"
        payload = await self._get_json(url)
        if payload is None:
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            return None
        downloads = data.get("last_month")
        return downloads if isinstance(downloads, int) else None

    def _evaluate(self, snapshot: MaintainerSnapshot) -> list[MaintainerFinding]:
        """Turn a snapshot into anomaly findings."""

        findings: list[MaintainerFinding] = []
        now = datetime.now(timezone.utc)
        popular = snapshot.downloads is not None and snapshot.downloads > 1_000_000
        if snapshot.created_at is not None and (now - snapshot.created_at) <= timedelta(days=30):
            if snapshot.last_release_at is not None and (now - snapshot.last_release_at) <= timedelta(days=30):
                findings.append(
                    MaintainerFinding(
                        label="New owner or package with recent release activity",
                        severity=self._cap_severity(Severity.HIGH, popular),
                        evidence_text=f"created_at={snapshot.created_at}; last_release_at={snapshot.last_release_at}",
                    )
                )
        if (
            not popular
            and snapshot.last_release_at is not None
            and snapshot.previous_release_at is not None
            and (now - snapshot.last_release_at) <= timedelta(days=30)
            and (snapshot.last_release_at - snapshot.previous_release_at) > timedelta(days=365 * 3)
        ):
            findings.append(
                MaintainerFinding(
                    label="Dormant package returned after more than three years",
                    severity=self._cap_severity(Severity.HIGH, popular),
                    evidence_text=(
                        f"previous_release_at={snapshot.previous_release_at}; "
                        f"last_release_at={snapshot.last_release_at}; downloads={snapshot.downloads}"
                    ),
                )
            )
        if (
            snapshot.single_maintainer
            and snapshot.downloads is not None
            and snapshot.downloads >= 10_000_000
            and snapshot.last_release_at is not None
            and (now - snapshot.last_release_at) <= timedelta(days=30)
        ):
            findings.append(
                MaintainerFinding(
                    label="High-download single-maintainer package changed hands",
                    severity=self._cap_severity(Severity.CRITICAL, popular),
                    evidence_text=f"downloads={snapshot.downloads}; maintainers={','.join(snapshot.maintainers)}",
                )
            )
        if (
            snapshot.release_count <= 1
            and snapshot.created_at is not None
            and (now - snapshot.created_at) <= timedelta(days=30)
        ):
            findings.append(
                MaintainerFinding(
                    label="Package appears newly published with little release history",
                    severity=self._cap_severity(Severity.MEDIUM, popular),
                    evidence_text=f"release_count={snapshot.release_count}; created_at={snapshot.created_at}",
                )
            )
        if snapshot.security_holding:
            findings.append(
                MaintainerFinding(
                    label="Package is in registry security holding quarantine",
                    severity=Severity.CRITICAL,
                    evidence_text=f"security_holding=true; versions_count={snapshot.release_count}",
                )
            )
        return findings

    def _cap_severity(self, severity: Severity, popular: bool) -> Severity:
        """Reduce maintainer anomaly severity for popular packages."""

        if popular and severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}:
            return Severity.LOW
        return severity


def infer_ecosystem(target: ScanTarget) -> str:
    """Infer npm versus PyPI from target metadata."""

    source = (target.source or "").lower()
    if source in {"npm", "node", "javascript"}:
        return "npm"
    if target.name.startswith("@") or "/" in target.name:
        return "npm"
    return "pypi"


def parse_package_json_metadata(
    text: str,
    package_name: str,
    maintainers: set[str],
) -> tuple[str, set[str]]:
    """Parse npm metadata from package.json."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return package_name, maintainers
    if not isinstance(payload, dict):
        return package_name, maintainers
    name = payload.get("name")
    if isinstance(name, str) and name:
        package_name = name
    author = payload.get("author")
    if isinstance(author, str) and author:
        maintainers.add(author)
    if isinstance(author, dict):
        name_value = author.get("name")
        if isinstance(name_value, str) and name_value:
            maintainers.add(name_value)
    contributors = payload.get("contributors")
    if isinstance(contributors, list):
        for entry in contributors:
            if isinstance(entry, str) and entry:
                maintainers.add(entry)
            elif isinstance(entry, dict):
                name_value = entry.get("name")
                if isinstance(name_value, str) and name_value:
                    maintainers.add(name_value)
    return package_name, maintainers


def parse_pyproject_metadata(
    text: str,
    package_name: str,
    maintainers: set[str],
) -> tuple[str, set[str]]:
    """Parse maintainers from pyproject.toml heuristically."""

    lower = text.lower()
    for key in ("maintainer", "author"):
        if key in lower:
            maintainers.add("local-maintainer")
    return package_name, maintainers


def parse_setup_py_name(text: str) -> str | None:
    """Extract a setup.py package name heuristically."""

    marker = "name="
    index = text.find(marker)
    if index == -1:
        return None
    remainder = text[index + len(marker) : index + len(marker) + 120]
    for quote in ('"', "'"):
        if remainder.startswith(quote):
            end = remainder.find(quote, 1)
            if end > 1:
                return remainder[1:end]
    return None


def parse_npm_maintainers(payload: dict[str, Any]) -> list[str]:
    """Parse npm maintainers from registry payload."""

    maintainers = payload.get("maintainers")
    if not isinstance(maintainers, list):
        return []
    names: list[str] = []
    for item in maintainers:
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


def parse_pypi_maintainers(payload: dict[str, Any]) -> list[str]:
    """Parse PyPI maintainers from registry payload."""

    info = payload.get("info")
    if not isinstance(info, dict):
        return []
    maintainers = []
    for key in ("maintainer", "author"):
        value = info.get(key)
        if isinstance(value, str) and value:
            maintainers.append(value)
    return maintainers


def parse_datetime_from_payload(payload: dict[str, Any], path: tuple[str, str]) -> datetime | None:
    """Parse a nested datetime from a registry payload."""

    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if not isinstance(current, str):
        return None
    return parse_datetime(current)


def parse_npm_release_timestamps(payload: dict[str, Any]) -> list[datetime]:
    """Parse npm release timestamps in ascending order."""

    time_data = payload.get("time")
    if not isinstance(time_data, dict):
        return []
    timestamps = []
    for key, value in time_data.items():
        if key in {"created", "modified"} or not isinstance(value, str):
            continue
        parsed = parse_datetime(value)
        if parsed is not None:
            timestamps.append(parsed)
    return sorted(timestamps)


def count_npm_versions(payload: dict[str, Any]) -> int:
    """Count npm published versions."""

    versions = payload.get("versions")
    return len(versions) if isinstance(versions, dict) else 0


def parse_pypi_release_timestamps(payload: dict[str, Any]) -> list[datetime]:
    """Parse PyPI release upload timestamps in ascending order."""

    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return []
    timestamps: list[datetime] = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for file_info in files:
            if isinstance(file_info, dict):
                uploaded = file_info.get("upload_time_iso_8601")
                if isinstance(uploaded, str):
                    parsed = parse_datetime(uploaded)
                    if parsed is not None:
                        timestamps.append(parsed)
    return sorted(timestamps)


def count_pypi_versions(payload: dict[str, Any]) -> int:
    """Count PyPI release versions."""

    releases = payload.get("releases")
    return len(releases) if isinstance(releases, dict) else 0


def parse_datetime(value: str) -> datetime | None:
    """Parse a registry timestamp into UTC."""

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
