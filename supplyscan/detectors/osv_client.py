"""OSV API client for known vulnerability lookups."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvVulnerability(BaseModel):
    """Normalized vulnerability returned by OSV."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    severity: str | None = None
    affected_ranges: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    published: datetime = Field(default_factory=lambda: datetime.fromtimestamp(0, tz=timezone.utc))
    url: str


async def query_osv(package: str, version: str | None, ecosystem: str) -> list[OsvVulnerability]:
    """Query OSV for vulnerabilities affecting a package."""

    body: dict[str, Any] = {
        "package": {
            "name": package,
            "ecosystem": normalize_osv_ecosystem(ecosystem),
        }
    }
    payload = await post_json_with_backoff(OSV_QUERY_URL, body)
    vulns = payload.get("vulns") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        return []
    return [parse_osv_vulnerability(item) for item in vulns if isinstance(item, dict)]


async def post_json_with_backoff(url: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST JSON with exponential backoff for transient and rate-limit errors."""

    headers = {"User-Agent": "SupplyScan/0.1", "Accept": "application/json"}
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, headers=headers) as client:
        for attempt in range(4):
            try:
                response = await client.post(url, json=body)
                if response.status_code in {429, 500, 502, 503, 504}:
                    await asyncio.sleep(backoff_delay(attempt, response))
                    continue
                response.raise_for_status()
                payload = response.json()
                return payload if isinstance(payload, dict) else {}
            except (httpx.HTTPError, json.JSONDecodeError):
                if attempt == 3:
                    raise
                await asyncio.sleep(backoff_delay(attempt, None))
    return {}


def parse_osv_vulnerability(payload: dict[str, Any]) -> OsvVulnerability:
    """Parse one raw OSV vulnerability object."""

    vuln_id = string_value(payload.get("id"), "OSV-UNKNOWN")
    aliases = string_list(payload.get("aliases"))
    summary = string_value(payload.get("summary") or payload.get("details"), "")
    severity = parse_osv_severity(payload)
    affected_ranges, fixed_versions = parse_osv_affected(payload.get("affected"))
    published = parse_datetime(string_value(payload.get("published"), ""))
    references = payload.get("references")
    url = first_reference_url(references) or f"https://osv.dev/vulnerability/{vuln_id}"
    return OsvVulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary,
        severity=severity,
        affected_ranges=affected_ranges,
        fixed_versions=fixed_versions,
        published=published,
        url=url,
    )


def parse_osv_severity(payload: dict[str, Any]) -> str | None:
    """Extract the strongest textual severity available in an OSV record."""

    database_specific = payload.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity:
            return severity.upper()
    severities = payload.get("severity")
    if isinstance(severities, list):
        for item in severities:
            if isinstance(item, dict):
                score = item.get("score")
                if isinstance(score, str) and score:
                    return score
    return None


def parse_osv_affected(value: object) -> tuple[list[str], list[str]]:
    """Extract affected specifier ranges and fixed versions from OSV affected blocks."""

    if not isinstance(value, list):
        return [], []
    ranges: list[str] = []
    fixed_versions: list[str] = []
    for affected in value:
        if not isinstance(affected, dict):
            continue
        versions = affected.get("versions")
        if isinstance(versions, list):
            ranges.extend(f"=={version}" for version in string_list(versions))
        range_blocks = affected.get("ranges")
        if isinstance(range_blocks, list):
            for range_block in range_blocks:
                if isinstance(range_block, dict):
                    block_ranges, block_fixed = parse_osv_range_events(range_block.get("events"))
                    ranges.extend(block_ranges)
                    fixed_versions.extend(block_fixed)
    return dedupe(ranges), dedupe(fixed_versions)


def parse_osv_range_events(value: object) -> tuple[list[str], list[str]]:
    """Convert OSV event ranges into packaging-compatible specifier strings."""

    if not isinstance(value, list):
        return [], []
    ranges: list[str] = []
    fixed_versions: list[str] = []
    introduced: str | None = None
    for event in value:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            raw = string_value(event.get("introduced"), "")
            introduced = None if raw in {"", "0"} else raw
        elif "fixed" in event:
            fixed = string_value(event.get("fixed"), "")
            if fixed:
                fixed_versions.append(fixed)
                ranges.append(format_range(introduced, f"<{fixed}"))
            introduced = None
        elif "last_affected" in event:
            last_affected = string_value(event.get("last_affected"), "")
            if last_affected:
                ranges.append(format_range(introduced, f"<={last_affected}"))
            introduced = None
        elif "limit" in event:
            limit = string_value(event.get("limit"), "")
            if limit:
                ranges.append(format_range(introduced, f"<{limit}"))
            introduced = None
    if introduced is not None:
        ranges.append(f">={introduced}")
    return ranges, fixed_versions


def format_range(introduced: str | None, upper_bound: str) -> str:
    """Format one introduced/fixed OSV range as a specifier set."""

    if introduced:
        return f">={introduced},{upper_bound}"
    return upper_bound


def normalize_osv_ecosystem(ecosystem: str) -> str:
    """Map local ecosystem names to OSV ecosystem identifiers."""

    normalized = ecosystem.lower()
    if normalized in {"npm", "node", "javascript"}:
        return "npm"
    return "PyPI"


def first_reference_url(value: object) -> str | None:
    """Return the first URL in an OSV references list."""

    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, dict):
            url = item.get("url")
            if isinstance(url, str) and url:
                return url
    return None


def parse_datetime(value: str) -> datetime:
    """Parse an OSV timestamp, falling back to the Unix epoch."""

    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def string_value(value: object, fallback: str) -> str:
    """Return a non-empty string value or a fallback."""

    return value if isinstance(value, str) and value else fallback


def string_list(value: object) -> list[str]:
    """Return all non-empty string entries from a list-like value."""

    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def dedupe(values: list[str]) -> list[str]:
    """Return a stable de-duplicated list."""

    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def backoff_delay(attempt: int, response: httpx.Response | None) -> float:
    """Return a bounded exponential backoff delay."""

    if response is not None:
        retry_after = response.headers.get("retry-after")
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 5.0)
    return min(0.5 * (2**attempt), 5.0)
