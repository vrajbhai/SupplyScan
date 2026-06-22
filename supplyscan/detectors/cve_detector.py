"""Known CVE and advisory detector."""

from __future__ import annotations

import asyncio
import json
import math
import re
from typing import Any

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import ResultBuilder, evidence, max_severity
from supplyscan.detectors.osv_client import OsvVulnerability, query_osv
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity


PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
PYPI_VERSION_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
NPM_AUDIT_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class VulnerabilityAdvisory(BaseModel):
    """Normalized advisory from OSV, PyPI, or GitHub."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(min_length=1)
    advisory_id: str = Field(min_length=1)
    cve_id: str | None = None
    ghsa_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None
    summary: str = ""
    affected_ranges: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    url: str

    @property
    def canonical_id(self) -> str:
        """Return the best stable advisory identifier for de-duplication."""

        return self.cve_id or self.ghsa_id or self.advisory_id


class AdvisorySourceResult(BaseModel):
    """Result from one advisory source."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(min_length=1)
    advisories: list[VulnerabilityAdvisory] = Field(default_factory=list)
    error: str | None = None


class CveDetector:
    """Detect known vulnerable package versions from public advisory databases."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        """Create a CVE detector."""

        self.http_client = http_client
        self.result_builder = ResultBuilder(detector_name="cve")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan a package target against OSV, PyPI, and GitHub advisories."""

        ecosystems = infer_ecosystems(target)
        results = await asyncio.gather(
            *(self._scan_ecosystem(target, ecosystem) for ecosystem in ecosystems)
        )
        flattened_results = [item for batch in results for item in batch]
        advisories = dedupe_advisories(
            [advisory for result in flattened_results for advisory in result.advisories]
        )
        advisories = [advisory for advisory in advisories if not is_withdrawn_advisory(advisory)]
        errors = [result for result in flattened_results if result.error is not None]
        if len(errors) == len(flattened_results):
            return self.result_builder.clean(
                [
                    evidence(
                        "cve-api",
                        "; ".join(f"{result.source}: {result.error}" for result in errors),
                    )
                ]
            )

        applicable = [
            advisory
            for advisory in advisories
            if advisory_applies_to_version(advisory, target.version)
        ]
        if not applicable:
            evidence_items = [
                evidence("cve-api", f"{result.source} unavailable: {result.error}")
                for result in errors
            ]
            return self.result_builder.clean(evidence_items)

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO
        for advisory in applicable:
            advisory_severity = advisory.severity
            if target.version is None:
                advisory_severity = max_severity(advisory_severity, Severity.MEDIUM)
            severity = max_severity(severity, advisory_severity)
            finding_id = advisory.cve_id or advisory.ghsa_id or advisory.advisory_id
            fixed = fixed_version_text(advisory.fixed_versions)
            summary = truncate(advisory.summary, 100)
            findings.append(f"{finding_id}: {summary}")
            evidence_items.append(
                evidence(
                    finding_id,
                    f"severity={advisory_severity.value}; url={advisory.url}; {fixed}; source={advisory.source}",
                )
            )
        return self.result_builder.build(findings, evidence_items, severity)

    async def _scan_ecosystem(self, target: ScanTarget, ecosystem: str) -> list[AdvisorySourceResult]:
        """Query all advisory sources for one ecosystem."""

        return await asyncio.gather(
            self._query_osv_source(target, ecosystem),
            self._query_pypi_source(target) if ecosystem == "pypi" else self._empty_source_result("pypi"),
            self._query_github_source(target, ecosystem),
            self._query_npm_audit_source(target) if ecosystem == "npm" else self._empty_source_result("npm-audit"),
        )

    async def _query_osv_source(self, target: ScanTarget, ecosystem: str) -> AdvisorySourceResult:
        """Query OSV and convert vulnerabilities into normalized advisories."""

        try:
            vulnerabilities = await query_osv(target.name, target.version, ecosystem)
        except (httpx.HTTPError, json.JSONDecodeError):
            return AdvisorySourceResult(source="osv", error="OSV API unavailable")
        advisories = [advisory_from_osv(vulnerability) for vulnerability in vulnerabilities]
        return AdvisorySourceResult(source="osv", advisories=advisories)

    async def _query_pypi_source(self, target: ScanTarget) -> AdvisorySourceResult:
        """Query PyPI advisory metadata for a package."""

        if target.version:
            url = PYPI_VERSION_JSON_URL.format(package=target.name, version=target.version)
            payload = await self._get_json_with_backoff(url, "pypi")
            version_specific = True
            if payload is None:
                payload = await self._get_json_with_backoff(PYPI_JSON_URL.format(package=target.name), "pypi")
                version_specific = False
        else:
            payload = await self._get_json_with_backoff(PYPI_JSON_URL.format(package=target.name), "pypi")
            version_specific = False
        if payload is None:
            return AdvisorySourceResult(source="pypi", error="PyPI advisory API unavailable")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
        advisories = [
            advisory_from_pypi(item, target.version if version_specific else None)
            for item in vulnerabilities
            if isinstance(item, dict)
        ]
        return AdvisorySourceResult(source="pypi", advisories=advisories)

    async def _query_github_source(self, target: ScanTarget, ecosystem: str) -> AdvisorySourceResult:
        """Query GitHub Advisory Database for advisories affecting a package."""

        payload = await self._get_json_with_backoff(
            GITHUB_ADVISORY_URL,
            "github",
            params={"affects": target.name},
        )
        if payload is None:
            return AdvisorySourceResult(source="github", error="GitHub advisory API unavailable")
        if not isinstance(payload, list):
            return AdvisorySourceResult(source="github", advisories=[])
        advisories = parse_github_advisory_list(payload, target.name, ecosystem)
        return AdvisorySourceResult(source="github", advisories=advisories)

    async def _query_npm_audit_source(self, target: ScanTarget) -> AdvisorySourceResult:
        """Query the npm audit bulk advisory endpoint for npm packages."""

        if target.version is None:
            return AdvisorySourceResult(source="npm-audit", advisories=[])
        payload = await self._post_json_with_backoff(
            NPM_AUDIT_URL,
            "npm-audit",
            {target.name: [target.version]},
        )
        if payload is None:
            return AdvisorySourceResult(source="npm-audit", error="npm audit advisory API unavailable")
        advisories = parse_npm_audit_payload(payload, target.name)
        return AdvisorySourceResult(source="npm-audit", advisories=advisories)

    async def _empty_source_result(self, source: str) -> AdvisorySourceResult:
        """Return a placeholder source result for skipped ecosystem queries."""

        return AdvisorySourceResult(source=source, advisories=[])

    async def _get_json_with_backoff(
        self,
        url: str,
        source: str,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """GET JSON with exponential backoff for rate limits and transient failures."""

        headers = {
            "Accept": "application/json",
            "User-Agent": "SupplyScan/0.1",
        }
        for attempt in range(4):
            try:
                if self.http_client is not None:
                    response = await self.http_client.get(
                        url,
                        params=params,
                        headers=headers,
                        timeout=10.0,
                    )
                else:
                    async with httpx.AsyncClient(follow_redirects=True) as client:
                        response = await client.get(
                            url,
                            params=params,
                            headers=headers,
                            timeout=10.0,
                        )
                if response.status_code in {429, 500, 502, 503, 504}:
                    await asyncio.sleep(backoff_delay(attempt, response))
                    continue
                if response.status_code >= 400:
                    return None
                return response.json()
            except (httpx.HTTPError, json.JSONDecodeError):
                if attempt == 3:
                    return None
                await asyncio.sleep(backoff_delay(attempt, None))
        return None

    async def _post_json_with_backoff(
        self,
        url: str,
        source: str,
        body: dict[str, Any],
    ) -> dict[str, Any] | list[Any] | None:
        """POST JSON with exponential backoff for rate limits and transient failures."""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SupplyScan/0.1",
        }
        for attempt in range(4):
            try:
                if self.http_client is not None:
                    response = await self.http_client.post(
                        url,
                        headers=headers,
                        json=body,
                        timeout=10.0,
                    )
                else:
                    async with httpx.AsyncClient(follow_redirects=True) as client:
                        response = await client.post(
                            url,
                            headers=headers,
                            json=body,
                            timeout=10.0,
                        )
                if response.status_code in {429, 500, 502, 503, 504}:
                    await asyncio.sleep(backoff_delay(attempt, response))
                    continue
                if response.status_code >= 400:
                    return None
                data = response.json()
                return data if isinstance(data, (dict, list)) else None
            except (httpx.HTTPError, json.JSONDecodeError):
                if attempt == 3:
                    return None
                await asyncio.sleep(backoff_delay(attempt, None))
        return None


def advisory_from_osv(vulnerability: OsvVulnerability) -> VulnerabilityAdvisory:
    """Convert an OSV vulnerability into a normalized advisory."""

    cve_id = first_cve([vulnerability.id, *vulnerability.aliases])
    ghsa_id = first_ghsa([vulnerability.id, *vulnerability.aliases])
    severity, score = severity_from_value(vulnerability.severity)
    return VulnerabilityAdvisory(
        source="osv",
        advisory_id=vulnerability.id,
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        aliases=vulnerability.aliases,
        severity=severity,
        cvss_score=score,
        summary=vulnerability.summary,
        affected_ranges=vulnerability.affected_ranges,
        fixed_versions=vulnerability.fixed_versions,
        url=vulnerability.url,
    )


def advisory_from_pypi(payload: dict[str, Any], exact_version: str | None = None) -> VulnerabilityAdvisory:
    """Convert a PyPI vulnerability entry into a normalized advisory."""

    advisory_id = string_value(payload.get("id"), "PYPI-UNKNOWN")
    aliases = string_list(payload.get("aliases"))
    cve_id = first_cve([advisory_id, *aliases])
    ghsa_id = first_ghsa([advisory_id, *aliases])
    fixed_versions = string_list(payload.get("fixed_in"))
    severity, score = severity_from_value(payload.get("severity") or payload.get("cvss"))
    if severity == Severity.MEDIUM and score is None:
        severity, score = severity_from_pypi_payload(payload)
    return VulnerabilityAdvisory(
        source="pypi",
        advisory_id=advisory_id,
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        aliases=aliases,
        severity=severity,
        cvss_score=score,
        summary=string_value(payload.get("details") or payload.get("summary"), ""),
        affected_ranges=[f"=={exact_version}"] if exact_version else [],
        fixed_versions=fixed_versions,
        url=string_value(payload.get("link") or payload.get("url"), f"https://pypi.org/project/{advisory_id}/"),
    )


def parse_npm_audit_payload(payload: dict[str, Any] | list[Any], package_name: str) -> list[VulnerabilityAdvisory]:
    """Parse npm audit bulk advisory response payloads."""

    raw_items: list[Any] = []
    if isinstance(payload, dict):
        package_items = payload.get(package_name)
        if isinstance(package_items, list):
            raw_items = package_items
        elif isinstance(package_items, dict):
            raw_items = [package_items]
        else:
            raw_items = list(payload.values())
    elif isinstance(payload, list):
        raw_items = payload

    advisories: list[VulnerabilityAdvisory] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        if "name" in item and string_value(item.get("name"), package_name).lower() != package_name.lower():
            continue
        advisories.append(advisory_from_npm_audit(item))
    return advisories


def advisory_from_npm_audit(payload: dict[str, Any]) -> VulnerabilityAdvisory:
    """Convert an npm audit advisory into a normalized advisory."""

    advisory_id = string_value(payload.get("id") or payload.get("url"), "NPM-UNKNOWN")
    cves = string_list(payload.get("cves"))
    cwe = string_list(payload.get("cwe"))
    aliases = dedupe([*cves, *cwe])
    cve_id = first_cve([advisory_id, *aliases])
    ghsa_id = first_ghsa([advisory_id, *aliases, string_value(payload.get("url"), "")])
    severity, score = severity_from_value(payload.get("cvss") or payload.get("severity"))
    vulnerable_versions = string_value(payload.get("vulnerable_versions"), "")
    patched_versions = string_value(payload.get("patched_versions"), "")
    fixed_versions = fixed_versions_from_npm_patched(patched_versions)
    return VulnerabilityAdvisory(
        source="npm-audit",
        advisory_id=advisory_id,
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        aliases=aliases,
        severity=severity,
        cvss_score=score,
        summary=string_value(payload.get("title") or payload.get("overview"), ""),
        affected_ranges=[convert_npm_range(vulnerable_versions)] if vulnerable_versions else [],
        fixed_versions=fixed_versions,
        url=string_value(payload.get("url"), "https://www.npmjs.com/advisories"),
    )


def advisories_from_github(
    payload: dict[str, Any],
    package_name: str,
    ecosystem: str,
) -> list[VulnerabilityAdvisory]:
    """Convert a GitHub advisory payload into package-specific advisories."""

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []
    ranges: list[str] = []
    fixed_versions: list[str] = []
    matched = False
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        package = vulnerability.get("package")
        if not isinstance(package, dict):
            continue
        if not github_package_matches(package, package_name, ecosystem):
            continue
        matched = True
        vulnerable_range = vulnerability.get("vulnerable_version_range")
        if isinstance(vulnerable_range, str) and vulnerable_range:
            ranges.append(convert_github_range(vulnerable_range))
        patched = vulnerability.get("first_patched_version")
        if isinstance(patched, str) and patched:
            fixed_versions.append(patched)
        elif isinstance(patched, dict):
            identifier = patched.get("identifier")
            if isinstance(identifier, str) and identifier:
                fixed_versions.append(identifier)
    if not matched:
        return []
    ghsa_id = string_value(payload.get("ghsa_id"), "")
    identifiers = payload.get("identifiers")
    identifier_values = identifiers_to_strings(identifiers)
    cve_id = first_cve([string_value(payload.get("cve_id"), ""), *identifier_values])
    severity, score = severity_from_github_payload(payload)
    advisory = VulnerabilityAdvisory(
        source="github",
        advisory_id=ghsa_id or cve_id or "GHSA-UNKNOWN",
        cve_id=cve_id,
        ghsa_id=ghsa_id or None,
        aliases=dedupe([*identifier_values, *string_list(payload.get("aliases"))]),
        severity=severity,
        cvss_score=score,
        summary=string_value(payload.get("summary") or payload.get("description"), ""),
        affected_ranges=dedupe(ranges),
        fixed_versions=dedupe(fixed_versions),
        url=string_value(payload.get("html_url") or payload.get("url"), "https://github.com/advisories"),
    )
    return [advisory]


def parse_github_advisory_list(
    payload: list[Any],
    package_name: str,
    ecosystem: str,
) -> list[VulnerabilityAdvisory]:
    """Parse GitHub advisory list results, accepting both expanded and compact shapes."""

    advisories: list[VulnerabilityAdvisory] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        expanded = advisories_from_github(item, package_name, ecosystem)
        if expanded:
            advisories.extend(expanded)
            continue
        compact = advisory_from_compact_github(item, package_name, ecosystem)
        if compact is not None:
            advisories.append(compact)
    return advisories


def advisory_from_compact_github(
    payload: dict[str, Any],
    package_name: str,
    ecosystem: str,
) -> VulnerabilityAdvisory | None:
    """Parse compact GitHub advisory entries that carry package fields at top level."""

    package = payload.get("package")
    if isinstance(package, dict) and not github_package_matches(package, package_name, ecosystem):
        return None
    if package is not None and not isinstance(package, dict):
        return None
    identifiers = identifiers_to_strings(payload.get("identifiers"))
    ghsa_id = string_value(payload.get("ghsa_id"), "") or first_ghsa(identifiers) or ""
    cve_id = first_cve([string_value(payload.get("cve_id"), ""), *identifiers])
    if not ghsa_id and not cve_id:
        return None
    ranges: list[str] = []
    fixed_versions: list[str] = []
    vulnerable_range = payload.get("vulnerable_version_range")
    if isinstance(vulnerable_range, str) and vulnerable_range:
        ranges.append(convert_github_range(vulnerable_range))
    patched = payload.get("first_patched_version")
    if isinstance(patched, str) and patched:
        fixed_versions.append(patched)
    elif isinstance(patched, dict):
        identifier = patched.get("identifier")
        if isinstance(identifier, str) and identifier:
            fixed_versions.append(identifier)
    severity, score = severity_from_github_payload(payload)
    return VulnerabilityAdvisory(
        source="github",
        advisory_id=ghsa_id or cve_id,
        cve_id=cve_id,
        ghsa_id=ghsa_id or None,
        aliases=dedupe([*identifiers, *string_list(payload.get("aliases"))]),
        severity=severity,
        cvss_score=score,
        summary=string_value(payload.get("summary") or payload.get("description"), ""),
        affected_ranges=dedupe(ranges),
        fixed_versions=dedupe(fixed_versions),
        url=string_value(payload.get("html_url") or payload.get("url"), "https://github.com/advisories"),
    )


def dedupe_advisories(advisories: list[VulnerabilityAdvisory]) -> list[VulnerabilityAdvisory]:
    """Merge duplicate advisories by CVE, GHSA, or source advisory ID."""

    merged: dict[str, VulnerabilityAdvisory] = {}
    for advisory in advisories:
        key = advisory.canonical_id.upper()
        if key not in merged:
            merged[key] = advisory
            continue
        merged[key] = merge_advisory(merged[key], advisory)
    return list(merged.values())


def merge_advisory(left: VulnerabilityAdvisory, right: VulnerabilityAdvisory) -> VulnerabilityAdvisory:
    """Merge two normalized advisories for the same vulnerability."""

    severity = max_severity(left.severity, right.severity)
    score = max_optional_float(left.cvss_score, right.cvss_score)
    if score is not None:
        severity = max_severity(severity, severity_from_cvss(score))
    return left.model_copy(
        update={
            "source": ",".join(dedupe([left.source, right.source])),
            "cve_id": left.cve_id or right.cve_id,
            "ghsa_id": left.ghsa_id or right.ghsa_id,
            "aliases": dedupe([*left.aliases, *right.aliases]),
            "severity": severity,
            "cvss_score": score,
            "summary": left.summary or right.summary,
            "affected_ranges": dedupe([*left.affected_ranges, *right.affected_ranges]),
            "fixed_versions": dedupe([*left.fixed_versions, *right.fixed_versions]),
            "url": left.url if left.url != "https://github.com/advisories" else right.url,
        }
    )


def is_withdrawn_advisory(advisory: VulnerabilityAdvisory) -> bool:
    """Return whether an advisory is withdrawn or retracted."""

    summary = advisory.summary.strip().lower()
    return summary.startswith("withdrawn") or summary.startswith("retracted")


def advisory_applies_to_version(advisory: VulnerabilityAdvisory, version: str | None) -> bool:
    """Return whether an advisory applies to the requested package version."""

    if version is None:
        return True
    parsed_version = parse_version(version)
    if parsed_version is None:
        return False
    for affected_range in advisory.affected_ranges:
        if specifier_contains(affected_range, parsed_version):
            return True
    if not advisory.affected_ranges and advisory.fixed_versions:
        fixed_versions = [parse_version(item) for item in advisory.fixed_versions]
        comparable = [item for item in fixed_versions if item is not None]
        if comparable and parsed_version < min(comparable):
            return True
    return False


def specifier_contains(specifier: str, version: Version) -> bool:
    """Return whether a version is inside a packaging specifier set."""

    try:
        return SpecifierSet(specifier).contains(version, prereleases=True)
    except InvalidSpecifier:
        return False


def convert_github_range(value: str) -> str:
    """Convert GitHub advisory ranges into packaging specifiers."""

    normalized = re.sub(r"\s*,\s*", ",", value.strip())
    normalized = re.sub(r"(<=|>=|==|!=|~=|<|>)\s+", r"\1", normalized)
    normalized = re.sub(r"\s+(?=(?:<=|>=|==|!=|~=|<|>))", ",", normalized)
    normalized = re.sub(r",{2,}", ",", normalized)
    return normalized.strip(",")


def convert_npm_range(value: str) -> str:
    """Convert npm advisory ranges into packaging-compatible specifiers."""

    normalized = value.strip()
    normalized = normalized.replace("||", ",")
    normalized = re.sub(r"\s+", ",", normalized)
    normalized = re.sub(r"(<=|>=|==|!=|~=|<|>)\s*", r"\1", normalized)
    normalized = re.sub(r",{2,}", ",", normalized)
    return normalized.strip(",")


def fixed_versions_from_npm_patched(value: str) -> list[str]:
    """Extract fixed versions from npm patched_versions text."""

    if not value or value.strip() == "<0.0.0":
        return []
    versions: list[str] = []
    for match in re.finditer(r">=\s*([0-9][A-Za-z0-9.+!-]*)", value):
        versions.append(match.group(1))
    return dedupe(versions)


def severity_from_github_payload(payload: dict[str, Any]) -> tuple[Severity, float | None]:
    """Extract severity and CVSS score from a GitHub advisory payload."""

    cvss = payload.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if isinstance(score, (int, float)):
            return severity_from_cvss(float(score)), float(score)
    return severity_from_value(payload.get("severity"))


def severity_from_pypi_payload(payload: dict[str, Any]) -> tuple[Severity, float | None]:
    """Extract severity from known PyPI advisory fields."""

    aliases = string_list(payload.get("aliases"))
    if aliases:
        return Severity.HIGH, None
    return Severity.MEDIUM, None


def severity_from_value(value: object) -> tuple[Severity, float | None]:
    """Map advisory severity text or score into a SupplyScan severity."""

    if isinstance(value, (int, float)):
        score = float(value)
        return severity_from_cvss(score), score
    if not isinstance(value, str) or not value:
        return Severity.MEDIUM, None
    stripped = value.strip()
    if stripped.upper().startswith("CVSS:") and "/" in stripped:
        score = cvss_v3_base_score(stripped)
        if score is not None:
            return severity_from_cvss(score), score
        return Severity.MEDIUM, None
    numeric = first_float(stripped)
    if numeric is not None:
        return severity_from_cvss(numeric), numeric
    normalized = stripped.upper()
    if normalized in {"CRITICAL"}:
        return Severity.CRITICAL, None
    if normalized in {"HIGH", "IMPORTANT"}:
        return Severity.HIGH, None
    if normalized in {"MEDIUM", "MODERATE"}:
        return Severity.MEDIUM, None
    if normalized in {"LOW"}:
        return Severity.LOW, None
    return Severity.MEDIUM, None


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS score to SupplyScan severity."""

    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def cvss_v3_base_score(vector: str) -> float | None:
    """Calculate a CVSS v3 base score from a vector string."""

    metrics = parse_cvss_vector(vector)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics["S"]
        pr = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50},
        }[scope][metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        confidentiality = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
        integrity = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
        availability = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
    except KeyError:
        return None

    impact_sub_score = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope == "U":
        impact = 6.42 * impact_sub_score
    elif scope == "C":
        impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * ((impact_sub_score - 0.02) ** 15)
    else:
        return None
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        return round_up_1_decimal(min(impact + exploitability, 10.0))
    return round_up_1_decimal(min(1.08 * (impact + exploitability), 10.0))


def parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS vector into metric key/value pairs."""

    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    return metrics


def round_up_1_decimal(value: float) -> float:
    """Round a CVSS score up to one decimal as required by the CVSS specification."""

    return math.ceil(value * 10.0 - 1e-7) / 10.0


def fixed_version_text(fixed_versions: list[str]) -> str:
    """Render fixed-version guidance."""

    if not fixed_versions:
        return "fix=no fixed version published"
    return f"fix=upgrade to {', '.join(fixed_versions[:3])}"


def github_package_matches(package: dict[str, Any], package_name: str, ecosystem: str) -> bool:
    """Return whether a GitHub vulnerable package object matches the target."""

    name = package.get("name")
    if isinstance(name, str) and name.lower() != package_name.lower():
        return False
    package_ecosystem = package.get("ecosystem")
    if isinstance(package_ecosystem, str):
        expected = "npm" if ecosystem == "npm" else "pip"
        return package_ecosystem.lower() in {expected, ecosystem.lower()}
    return True


def infer_ecosystems(target: ScanTarget) -> list[str]:
    """Infer one or more ecosystems from target metadata."""

    source = (target.source or "").lower()
    if source in {"npm", "node", "javascript"}:
        return ["npm"]
    if source in {"pypi", "python", "requirements"}:
        return ["pypi"]
    if source in {"manual", "auto", "unknown", ""}:
        return ["npm", "pypi"]
    if target.name.startswith("@") or "/" in target.name:
        return ["npm"]
    return ["npm", "pypi"]


def parse_version(value: str) -> Version | None:
    """Parse a package version for comparisons."""

    try:
        return Version(value)
    except InvalidVersion:
        return None


def first_cve(values: list[str]) -> str | None:
    """Return the first CVE identifier in a list of strings."""

    for value in values:
        match = CVE_PATTERN.search(value)
        if match:
            return match.group(0).upper()
    return None


def first_ghsa(values: list[str]) -> str | None:
    """Return the first GHSA identifier in a list of strings."""

    for value in values:
        if value.upper().startswith("GHSA-"):
            return value.upper()
    return None


def first_float(value: str) -> float | None:
    """Extract the first numeric score from a string."""

    match = re.search(r"\d+(?:\.\d+)?", value)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def identifiers_to_strings(value: object) -> list[str]:
    """Extract identifier values from a GitHub advisory identifiers list."""

    if not isinstance(value, list):
        return []
    identifiers: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        identifier_value = item.get("value")
        if isinstance(identifier_value, str) and identifier_value:
            identifiers.append(identifier_value)
    return identifiers


def max_optional_float(left: float | None, right: float | None) -> float | None:
    """Return the maximum optional float."""

    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def truncate(value: str, limit: int) -> str:
    """Truncate text to a bounded display length."""

    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3].rstrip() + "..."


def string_value(value: object, fallback: str) -> str:
    """Return a non-empty string value or a fallback."""

    return value if isinstance(value, str) and value else fallback


def string_list(value: object) -> list[str]:
    """Return non-empty string values from a list."""

    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def dedupe(values: list[str]) -> list[str]:
    """Return a stable de-duplicated list."""

    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value and value not in seen:
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
