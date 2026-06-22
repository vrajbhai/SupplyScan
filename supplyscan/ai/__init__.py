"""AI explainer providers for SupplyScan."""

from supplyscan.ai.claude_explainer import ClaudeExplainer
from supplyscan.ai.explainer_router import ExplainerRouter, build_explainer_from_env
from supplyscan.ai.opencode_explainer import OpenCodeExplainer

__all__ = [
    "ClaudeExplainer",
    "ExplainerRouter",
    "OpenCodeExplainer",
    "build_explainer_from_env",
]
