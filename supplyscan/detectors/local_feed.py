"""Local offline threat feed detector checking against ProjectDiscovery malicious packages export."""

from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from platformdirs import user_data_path

import httpx

from supplyscan.detectors.common import ResultBuilder, evidence
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


DEFAULT_FEED_URL = "https://github.projectdiscovery.io/github/malicious/export"


class LocalFeedDetector:
    """Check scan targets against a synced local copy of the ProjectDiscovery malicious feed."""

    def __init__(
        self,
        feed_url: str = DEFAULT_FEED_URL,
        cache_dir: Path | None = None,
        cache_ttl_seconds: int = 3600 * 24,  # Cache feed for 24 hours
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create a local feed detector."""

        self.feed_url = feed_url
        self.cache_dir = cache_dir or user_data_path("SupplyScan", "SupplyScan")
        self.cache_path = self.cache_dir / "feed.json"
        self.cache_ttl_seconds = cache_ttl_seconds
        self.http_client = http_client
        self.result_builder = ResultBuilder(detector_name="local_feed")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan a package against the local synced threat database."""

        # Attempt to load or sync the feed
        feed_data = await self._ensure_feed_data()
        if not feed_data:
            return self.result_builder.clean([evidence("feed", "offline/no cache available")])

        ecosystem = self._normalize_ecosystem(target.source or "")
        package_name = target.name.lower().strip()
        target_version = target.version

        packages = feed_data.get("packages", [])
        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO

        for record in packages:
            if not isinstance(record, dict):
                continue
            rec_eco = record.get("ecosystem", "").lower()
            rec_name = record.get("name", "").lower().strip()
            if rec_eco != ecosystem or rec_name != package_name:
                continue

            # Verify version match
            all_versions = record.get("all_versions", False)
            affected_versions = record.get("affected_versions") or []
            is_malicious = False

            if all_versions or not target_version:
                is_malicious = True
            elif target_version in affected_versions:
                is_malicious = True

            if is_malicious:
                severity = Severity.CRITICAL
                summary = record.get("summary") or "Malicious package match in threat feed"
                vuln_ids = record.get("ids") or ["MAL-UNKNOWN"]
                primary_id = vuln_ids[0] if vuln_ids else "MAL-UNKNOWN"
                findings.append(f"{primary_id}: {summary}")
                evidence_items.append(
                    evidence(
                        primary_id,
                        f"summary={summary}; all_versions={all_versions}; source={record.get('source', 'unknown')}",
                    )
                )

        return self.result_builder.build(findings, evidence_items, severity)

    async def _ensure_feed_data(self) -> dict | None:
        """Ensure the feed is downloaded and return the parsed JSON dict."""

        is_stale = (
            not self.cache_path.exists()
            or (time.time() - self.cache_path.stat().st_mtime) > self.cache_ttl_seconds
        )

        if is_stale:
            try:
                await self._download_feed()
            except Exception:
                # If sync fails, fall back to whatever cached copy exists
                pass

        if not self.cache_path.exists():
            return None

        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    async def _download_feed(self) -> None:
        """Download the gzipped feed and decompress it to feed.json."""

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        headers = {"User-Agent": "SupplyScan/0.1", "Accept-Encoding": "gzip"}

        async def _fetch(client: httpx.AsyncClient) -> bytes:
            response = await client.get(self.feed_url, headers=headers, timeout=120.0)
            response.raise_for_status()
            return response.content

        if self.http_client is not None:
            content = await _fetch(self.http_client)
        else:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                content = await _fetch(client)

        # Decompress gzip payload if needed
        try:
            decompressed = gzip.decompress(content)
        except gzip.BadGzipFile:
            decompressed = content

        self.cache_path.write_bytes(decompressed)

    def _normalize_ecosystem(self, source: str) -> str:
        """Normalize package source labels to match the depx feed ecosystems."""

        lbl = source.lower()
        if lbl in {"npm", "node", "javascript", "js"}:
            return "npm"
        if lbl in {"pypi", "python", "pip", "requirements"}:
            return "pypi"
        return lbl
