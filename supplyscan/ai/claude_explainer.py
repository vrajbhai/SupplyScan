"""Claude threat explainer for SupplyScan."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from pydantic import ValidationError

from supplyscan.models import DetectorResult, ScanTarget, Severity, ThreatExplanation


CLAUDE_MODEL = "claude-sonnet-4-20250514"


class ClaudeExplainer:
    """Explain detector findings with Anthropic Claude."""

    def __init__(self, api_key: str | None = None, model: str = CLAUDE_MODEL) -> None:
        """Create a Claude explainer."""

        self.api_key = api_key or os.getenv("CLAUDE_API_KEY")
        self.model = model

    async def explain(
        self,
        target: ScanTarget,
        results: list[DetectorResult],
    ) -> ThreatExplanation | None:
        """Return a structured threat explanation for detector findings."""

        actionable_results = [result for result in results if result.has_findings]
        if not actionable_results:
            return None
        if not self.api_key:
            return None

        prompt = build_explainer_prompt(target, actionable_results)
        try:
            response_text = await self._complete(prompt)
            return parse_threat_explanation(response_text)
        except Exception as exc:
            return local_failure_explanation(target, actionable_results, f"Claude unavailable: {exc}")

    async def _complete(self, prompt: str) -> str:
        """Call Claude and return the response text."""

        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:
            raise ImportError("anthropic SDK is not installed") from exc

        client = AsyncAnthropic(api_key=self.api_key)
        message = await asyncio.wait_for(
            client.messages.create(
                model=self.model,
                max_tokens=600,
                temperature=0,
                system=(
                    "You are SupplyScan's security explainer. Return only valid JSON matching "
                    "this schema: {\"severity\":\"CRITICAL|HIGH|MEDIUM|LOW\","
                    "\"explanation\":\"exactly three plain-English sentences\","
                    "\"recommended_action\":\"short imperative action\"}."
                ),
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=30,
        )
        parts: list[str] = []
        for block in message.content:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        if not parts:
            raise RuntimeError("Claude returned an empty response")
        return "\n".join(parts)


def build_explainer_prompt(target: ScanTarget, results: list[DetectorResult]) -> str:
    """Build the provider-neutral threat explanation prompt."""

    payload = {
        "package": target.name,
        "version": target.version,
        "source": target.source,
        "detector_results": [
            {
                "name": result.name,
                "severity": result.severity.value,
                "findings": result.findings,
                "evidence": [
                    {"label": item.label, "value": item.value}
                    for item in result.evidence
                ],
            }
            for result in results
        ],
    }
    return (
        "Analyze this package supply-chain scan for a developer. "
        "Use the strongest detector severity unless the evidence clearly justifies a lower one. "
        "The explanation must be exactly three sentences, plain English, and avoid speculation. "
        "Return only JSON with severity, explanation, and recommended_action.\n\n"
        f"{json.dumps(payload, indent=2, sort_keys=True)}"
    )


def parse_threat_explanation(text: str) -> ThreatExplanation:
    """Parse a provider response into a ThreatExplanation."""

    payload = extract_json_object(text)
    severity = normalize_severity(payload.get("severity"))
    explanation = str(payload.get("explanation") or "").strip()
    recommended_action = str(payload.get("recommended_action") or "").strip()
    if not explanation:
        raise ValueError("missing explanation")
    if not recommended_action:
        raise ValueError("missing recommended_action")
    return ThreatExplanation(
        severity=severity,
        explanation=explanation,
        recommended_action=recommended_action,
    )


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from a model response."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].strip()
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("response did not contain a JSON object")
        payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("response JSON was not an object")
    return payload


def normalize_severity(value: object) -> Severity:
    """Normalize provider severity into a SupplyScan severity."""

    if not isinstance(value, str):
        return Severity.MEDIUM
    normalized = value.upper()
    if normalized == "CRITICAL":
        return Severity.CRITICAL
    if normalized == "HIGH":
        return Severity.HIGH
    if normalized == "MEDIUM":
        return Severity.MEDIUM
    if normalized == "LOW":
        return Severity.LOW
    return Severity.MEDIUM


def local_failure_explanation(
    target: ScanTarget,
    results: list[DetectorResult],
    reason: str,
) -> ThreatExplanation:
    """Return a deterministic explanation when a configured AI provider fails."""

    severity = highest_result_severity(results)
    top_findings = [finding for result in results for finding in result.findings][:3]
    finding_text = "; ".join(top_findings) if top_findings else "detectors reported suspicious signals"
    return ThreatExplanation(
        severity=severity,
        explanation=(
            f"SupplyScan detected suspicious behavior in {target.name}. "
            f"The strongest signals were: {finding_text}. "
            f"The AI provider could not complete analysis, so this explanation uses raw detector evidence."
        ),
        recommended_action=f"Block installation until reviewed manually; {reason}.",
    )


def is_provider_failure_explanation(explanation: ThreatExplanation | None) -> bool:
    """Return whether an explanation is the deterministic local provider-failure fallback."""

    if explanation is None:
        return False
    return (
        "provider could not complete analysis" in explanation.explanation.lower()
        or "unavailable:" in explanation.recommended_action.lower()
    )


def highest_result_severity(results: list[DetectorResult]) -> Severity:
    """Return the highest detector severity from a result list."""

    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    highest = Severity.INFO
    for result in results:
        if order[result.severity] > order[highest]:
            highest = result.severity
    return highest if highest != Severity.INFO else Severity.MEDIUM
