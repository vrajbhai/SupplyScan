"""Typosquatting and homoglyph detector."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

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


DEFAULT_POPULAR_PACKAGES = (
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "pydantic",
    "pytest",
    "setuptools",
    "wheel",
    "pip",
    "urllib3",
    "botocore",
    "boto3",
    "sqlalchemy",
    "cryptography",
    "colorama",
    "rich",
    "click",
    "httpx",
    "aiohttp",
    "tensorflow",
    "torch",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "beautifulsoup4",
    "selenium",
    "ansible",
    "express",
    "react",
    "react-dom",
    "vue",
    "angular",
    "lodash",
    "axios",
    "chalk",
    "debug",
    "commander",
    "typescript",
    "webpack",
    "babel-core",
    "eslint",
    "prettier",
    "moment",
    "uuid",
    "dotenv",
    "socket.io",
    "mongoose",
    "next",
    "vite",
)

HOMOGLYPHS = {
    "\u0430": "a",
    "\u0412": "B",
    "\u0415": "E",
    "\u0435": "e",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u043e": "o",
    "\u0420": "P",
    "\u0440": "p",
    "\u0421": "C",
    "\u0441": "c",
    "\u0422": "T",
    "\u0425": "X",
    "\u0445": "x",
    "\u0443": "y",
    "\u0406": "I",
    "\u0456": "i",
    "\u0408": "J",
    "\u0458": "j",
    "\u0501": "d",
    "\u217c": "l",
    "\uff10": "0",
    "\uff11": "1",
    "\uff13": "3",
    "\uff15": "5",
}


class NameSimilarity(BaseModel):
    """Similarity result against a popular package name."""

    model_config = ConfigDict(frozen=True)

    package: str = Field(min_length=1)
    distance: int = Field(ge=0)
    homoglyph: bool = False


class PackageFreshness(BaseModel):
    """Registry freshness data used for combo typosquat signals."""

    model_config = ConfigDict(frozen=True)

    is_new: bool
    created_at: datetime | None = None
    ecosystem: str = Field(min_length=1)


class TyposquatDetector:
    """Detect likely typosquats of popular PyPI and npm packages."""

    def __init__(
        self,
        popular_packages: Iterable[str] | None = None,
        max_distance: int = 2,
        new_package_days: int = 30,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create a typosquat detector."""

        self.popular_packages = tuple(
            sorted({normalize_name(name) for name in (popular_packages or DEFAULT_POPULAR_PACKAGES)})
        )
        self.max_distance = max_distance
        self.new_package_days = new_package_days
        self.http_client = http_client
        self.result_builder = ResultBuilder(detector_name="typosquat")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan a package name for typosquatting indicators."""

        package_name = normalize_name(target.name)
        similarities = self._find_similar_names(package_name, target.name)
        has_install_script = await has_local_install_script(target)
        freshness = await self._fetch_freshness(target)

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO

        for similarity in similarities:
            if similarity.homoglyph:
                severity = max_severity(severity, Severity.HIGH)
                findings.append(f"Unicode homoglyph package name resembles '{similarity.package}'")
            else:
                severity = max_severity(severity, Severity.MEDIUM)
                findings.append(
                    f"Package name is distance {similarity.distance} from '{similarity.package}'"
                )
            evidence_items.append(
                evidence(
                    "name-similarity",
                    f"{target.name} -> {similarity.package}; distance={similarity.distance}; "
                    f"homoglyph={similarity.homoglyph}",
                )
            )

        if similarities and freshness.is_new and has_install_script:
            severity = max_severity(severity, Severity.CRITICAL)
            findings.append("New similar package contains an install script")
            evidence_items.append(
                evidence(
                    "combo",
                    f"ecosystem={freshness.ecosystem}; created_at={freshness.created_at}; "
                    "install_script=true",
                )
            )
        elif has_install_script and similarities:
            severity = max_severity(severity, Severity.HIGH)
            findings.append("Similar package name includes install-time execution")
            evidence_items.append(evidence("install-script", "local source contains install script"))

        return self.result_builder.build(findings, evidence_items, severity)

    def _find_similar_names(self, normalized_name: str, original_name: str) -> list[NameSimilarity]:
        """Find popular package names close to the target name."""

        folded_name = fold_homoglyphs(original_name).lower()
        results: list[NameSimilarity] = []
        for popular in self.popular_packages:
            if normalized_name == popular:
                continue
            distance = levenshtein_distance(normalized_name, popular, max_distance=self.max_distance)
            homoglyph = folded_name == popular and original_name.lower() != folded_name
            if distance <= self.max_distance or homoglyph:
                results.append(
                    NameSimilarity(
                        package=popular,
                        distance=min(distance, self.max_distance),
                        homoglyph=homoglyph,
                    )
                )
        return sorted(results, key=lambda item: (not item.homoglyph, item.distance, item.package))[:5]

    async def _fetch_freshness(self, target: ScanTarget) -> PackageFreshness:
        """Fetch package creation freshness from the most likely registry."""

        ecosystem = infer_ecosystem(target)
        created_at = (
            await self._fetch_npm_created_at(target.name)
            if ecosystem == "npm"
            else await self._fetch_pypi_created_at(target.name)
        )
        if created_at is None:
            return PackageFreshness(is_new=False, created_at=None, ecosystem=ecosystem)
        age_days = (datetime.now(timezone.utc) - created_at).days
        return PackageFreshness(
            is_new=age_days <= self.new_package_days,
            created_at=created_at,
            ecosystem=ecosystem,
        )

    async def _fetch_pypi_created_at(self, package_name: str) -> datetime | None:
        """Fetch the earliest PyPI upload time for a package."""

        payload = await self._get_json(f"https://pypi.org/pypi/{package_name}/json")
        if payload is None:
            return None
        releases = payload.get("releases")
        if not isinstance(releases, dict):
            return None
        times: list[datetime] = []
        for files in releases.values():
            if not isinstance(files, list):
                continue
            for file_info in files:
                if not isinstance(file_info, dict):
                    continue
                uploaded = parse_datetime(file_info.get("upload_time_iso_8601"))
                if uploaded is not None:
                    times.append(uploaded)
        return min(times) if times else None

    async def _fetch_npm_created_at(self, package_name: str) -> datetime | None:
        """Fetch npm package creation time."""

        payload = await self._get_json(f"https://registry.npmjs.org/{package_name}")
        if payload is None:
            return None
        time_data = payload.get("time")
        if not isinstance(time_data, dict):
            return None
        return parse_datetime(time_data.get("created"))

    async def _get_json(self, url: str) -> dict[str, object] | None:
        """Fetch JSON from a registry endpoint."""

        async def _request(client: httpx.AsyncClient) -> dict[str, object] | None:
            """Execute a registry request."""

            response = await client.get(url, timeout=5.0)
            if response.status_code >= 400:
                return None
            data = response.json()
            return data if isinstance(data, dict) else None

        try:
            if self.http_client is not None:
                return await _request(self.http_client)
            async with httpx.AsyncClient(follow_redirects=True) as client:
                return await _request(client)
        except (httpx.HTTPError, json.JSONDecodeError):
            return None


async def has_local_install_script(target: ScanTarget) -> bool:
    """Return whether local source contains a package install script."""

    root = resolve_source_path(target)
    if root is None:
        return False
    for source_file in await collect_source_files(root, suffixes={".json", ".py", ".toml", ".js", ".cjs", ".mjs"}):
        normalized = source_file.relative_path.replace("\\", "/").lower()
        if normalized.endswith("package.json") and package_json_has_install_script(source_file.text):
            return True
        if normalized.endswith("setup.py") and setup_py_has_execution(source_file.text):
            return True
        if normalized.endswith("pyproject.toml") and "build-backend" in source_file.text:
            return True
    return False


def package_json_has_install_script(text: str) -> bool:
    """Return whether package.json contains an npm install lifecycle script."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    scripts = payload.get("scripts") if isinstance(payload, dict) else None
    if not isinstance(scripts, dict):
        return False
    return any(name in scripts for name in {"preinstall", "install", "postinstall", "prepare"})


def setup_py_has_execution(text: str) -> bool:
    """Return whether setup.py appears to perform install-time execution."""

    indicators = ("cmdclass", "subprocess", "os.system", "requests.", "httpx.", "urllib", "socket")
    return any(indicator in text for indicator in indicators)


def infer_ecosystem(target: ScanTarget) -> str:
    """Infer package ecosystem from name and local source."""

    if target.name.startswith("@") or "/" in target.name:
        return "npm"
    root = resolve_source_path(target)
    if root is None:
        return "pypi"
    package_json = root / "package.json" if root.is_dir() else Path("")
    return "npm" if package_json.exists() else "pypi"


def normalize_name(name: str) -> str:
    """Normalize a package name for edit-distance comparison."""

    return fold_homoglyphs(name).replace("_", "-").lower()


def fold_homoglyphs(value: str) -> str:
    """Replace common Unicode homoglyphs with ASCII equivalents."""

    return "".join(HOMOGLYPHS.get(character, character) for character in value)


def levenshtein_distance(left: str, right: str, max_distance: int | None = None) -> int:
    """Compute Levenshtein distance with optional early cutoff."""

    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        row_min = left_index
        for right_index, right_char in enumerate(right, start=1):
            insert_cost = current[right_index - 1] + 1
            delete_cost = previous[right_index] + 1
            replace_cost = previous[right_index - 1] + (left_char != right_char)
            value = min(insert_cost, delete_cost, replace_cost)
            current.append(value)
            row_min = min(row_min, value)
        if max_distance is not None and row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def parse_datetime(value: object) -> datetime | None:
    """Parse registry datetime values into UTC datetimes."""

    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
