"""AI explainer routing for SupplyScan."""

from __future__ import annotations

import os
from pathlib import Path

from supplyscan.ai.claude_explainer import ClaudeExplainer
from supplyscan.ai.opencode_explainer import OpenCodeExplainer
from supplyscan.models import DetectorResult, ScanTarget, ThreatExplanation


class ExplainerRouter:
    """Route explanation requests to the configured AI provider."""

    def __init__(
        self,
        claude_api_key: str | None = None,
        opencode_api_key: str | None = None,
    ) -> None:
        """Create a router using explicit keys or environment variables."""

        load_config_env()
        self.claude_api_key = claude_api_key if claude_api_key is not None else env_value("CLAUDE_API_KEY")
        self.opencode_api_key = (
            opencode_api_key
            if opencode_api_key is not None
            else env_value("OPENCODE_API_KEY", "OPENROUTER_API_KEY")
        )
        self.provider = self._select_provider()

    async def explain(
        self,
        target: ScanTarget,
        results: list[DetectorResult],
    ) -> ThreatExplanation | None:
        """Explain findings with the first available provider, or return None offline."""

        if self.provider is None:
            return None
        return await self.provider.explain(target, results)

    def _select_provider(self) -> ClaudeExplainer | OpenCodeExplainer | None:
        """Select Claude first, then OpenCode.ai, then offline mode."""

        if self.claude_api_key:
            return ClaudeExplainer(api_key=self.claude_api_key)
        if self.opencode_api_key:
            return OpenCodeExplainer(api_key=self.opencode_api_key)
        return None


def build_explainer_from_env() -> ExplainerRouter | None:
    """Build an explainer router from environment variables."""

    router = ExplainerRouter()
    return router if router.provider is not None else None


def load_config_env() -> None:
    """Load API keys from config.env or .env without overriding process environment."""

    for path in config_env_candidates():
        if not path.exists() or not path.is_file():
            continue
        for key, value in parse_env_file(path).items():
            os.environ.setdefault(key, value)


def config_env_candidates() -> list[Path]:
    """Return candidate config files from the workspace, install root, and user home."""

    candidates: list[Path] = [
        Path.cwd() / "config.env",
        Path.cwd() / ".env",
        Path.home() / ".supplyscan" / "config.env",
    ]
    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / "config.env")
        candidates.append(parent / ".env")

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.expanduser().resolve(strict=False)).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(candidate.expanduser())
    return deduped


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file."""

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and value:
            values[key] = value
    return values


def env_value(*names: str) -> str | None:
    """Return the first configured non-empty environment value."""

    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None
