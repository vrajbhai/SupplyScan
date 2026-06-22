"""OpenCode.ai threat explainer for SupplyScan."""

from __future__ import annotations

import os

import httpx
from pydantic import ValidationError

from supplyscan.ai.claude_explainer import (
    build_explainer_prompt,
    local_failure_explanation,
    parse_threat_explanation,
)
from supplyscan.models import DetectorResult, ScanTarget, ThreatExplanation


OPENCODE_CHAT_COMPLETIONS_URL = "https://opencode.ai/zen/v1/chat/completions"
OPENCODE_MODEL = "north-mini-code-free"
OPENCODE_FALLBACK_MODELS = (
    "north-mini-code-free",
    "deepseek-v4-flash-free",
    "mimo-v2.5-free",
    "big-pickle",
)


class OpenCodeExplainer:
    """Explain detector findings with the OpenCode chat completions API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str = OPENCODE_CHAT_COMPLETIONS_URL,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create an OpenCode.ai-backed explainer."""

        self.api_key = api_key or os.getenv("OPENCODE_API_KEY")
        self.model = model or os.getenv("OPENCODE_MODEL") or OPENCODE_MODEL
        self.base_url = base_url
        self.http_client = http_client

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
            response_text = await self._complete_with_fallbacks(prompt)
            return parse_threat_explanation(response_text)
        except (httpx.HTTPError, RuntimeError, TimeoutError, ValidationError, ValueError) as exc:
            return local_failure_explanation(target, actionable_results, f"OpenCode unavailable: {exc}")

    async def _complete_with_fallbacks(self, prompt: str) -> str:
        """Call OpenCode.ai, trying configured free models before failing."""

        models = ordered_models(self.model)
        errors: list[str] = []
        for model in models:
            try:
                return await self._complete(prompt, model)
            except (httpx.HTTPError, RuntimeError, TimeoutError, ValueError) as exc:
                errors.append(f"{model}: {exc}")
        raise RuntimeError("; ".join(errors))

    async def _complete(self, prompt: str, model: str) -> str:
        """Call the OpenCode.ai chat completions API and return content text."""

        payload = {
            "model": model,
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are SupplyScan's security explainer. Return only valid JSON matching "
                        "this schema: {\"severity\":\"CRITICAL|HIGH|MEDIUM|LOW\","
                        "\"explanation\":\"exactly three plain-English sentences\","
                        "\"recommended_action\":\"short imperative action\"}."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SupplyScan/0.1",
        }
        if self.http_client is not None:
            response = await self.http_client.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=30.0,
            )
        else:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.post(
                    self.base_url,
                    headers=headers,
                    json=payload,
                    timeout=30.0,
                )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("OpenCode.ai returned no choices")
        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise RuntimeError("OpenCode.ai returned malformed choice")
        message = first_choice.get("message")
        if not isinstance(message, dict):
            raise RuntimeError("OpenCode.ai returned malformed message")
        content = message.get("content")
        normalized = normalize_content(content)
        if not normalized:
            raise RuntimeError("OpenCode.ai returned empty content")
        return normalized


def ordered_models(primary_model: str) -> list[str]:
    """Return the primary model followed by known free OpenCode.ai fallbacks."""

    models = [primary_model, *OPENCODE_FALLBACK_MODELS]
    deduped: list[str] = []
    seen: set[str] = set()
    for model in models:
        if model not in seen:
            seen.add(model)
            deduped.append(model)
    return deduped


def normalize_content(content: object) -> str:
    """Normalize OpenAI-compatible message content into text."""

    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts).strip()
    return ""
