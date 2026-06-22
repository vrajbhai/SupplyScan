"""Global pip and npm hook manager for SupplyScan."""

from __future__ import annotations

import os
import shutil
import site
import sys
import sysconfig
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


PIP_BEGIN_MARKER = "# BEGIN SUPPLYSCAN PIP HOOK"
PIP_END_MARKER = "# END SUPPLYSCAN PIP HOOK"
NPM_BEGIN_MARKER = "# BEGIN SUPPLYSCAN NPM HOOK"
NPM_END_MARKER = "# END SUPPLYSCAN NPM HOOK"


class HookOperation(str, Enum):
    """Hook operation type."""

    INSTALL = "install"
    REMOVE = "remove"


class HookAction(BaseModel):
    """One hook manager action for user-visible reporting."""

    model_config = ConfigDict(frozen=True)

    target: str = Field(min_length=1)
    path: str = Field(min_length=1)
    status: str = Field(min_length=1)
    detail: str = Field(min_length=1)


class HookReport(BaseModel):
    """Result of hook installation or removal."""

    model_config = ConfigDict(frozen=True)

    operation: HookOperation
    actions: list[HookAction] = Field(default_factory=list)

    @property
    def changed(self) -> bool:
        """Return whether any hook action changed disk state."""

        return any(action.status == "changed" for action in self.actions)

    @property
    def has_errors(self) -> bool:
        """Return whether any hook action failed."""

        return any(action.status == "error" for action in self.actions)


class HookManager:
    """Install and remove SupplyScan pip and npm hooks."""

    def __init__(self, site_packages: Path | None = None, npmrc_path: Path | None = None) -> None:
        """Create a hook manager with optional explicit hook paths."""

        self.site_packages = site_packages
        self.npmrc_path = npmrc_path or Path.home() / ".npmrc"

    def install_hooks(self) -> HookReport:
        """Install pip and npm hooks and return a report."""

        actions = [self._install_pip_hook(), self._install_npm_hook()]
        return HookReport(operation=HookOperation.INSTALL, actions=actions)

    def remove_hooks(self) -> HookReport:
        """Remove pip and npm hooks and return a report."""

        actions = [self._remove_pip_hook(), self._remove_npm_hook()]
        return HookReport(operation=HookOperation.REMOVE, actions=actions)

    def _install_pip_hook(self) -> HookAction:
        """Install the pip sitecustomize hook."""

        sitecustomize_path = self._sitecustomize_path()
        try:
            return self._write_pip_hook(sitecustomize_path, fallback=False)
        except PermissionError as exc:
            fallback_path = self._user_sitecustomize_path()
            if fallback_path == sitecustomize_path:
                return HookAction(target="pip", path=str(sitecustomize_path), status="error", detail=str(exc))
            try:
                action = self._write_pip_hook(fallback_path, fallback=True)
            except OSError as fallback_exc:
                return HookAction(
                    target="pip",
                    path=str(fallback_path),
                    status="error",
                    detail=(
                        f"Global install denied at {sitecustomize_path}: {exc}; "
                        f"user-site fallback failed: {fallback_exc}"
                    ),
                )
            return action
        except OSError as exc:
            return HookAction(target="pip", path=str(sitecustomize_path), status="error", detail=str(exc))

    def _write_pip_hook(self, sitecustomize_path: Path, fallback: bool) -> HookAction:
        """Write the marked pip hook block to a sitecustomize.py path."""

        sitecustomize_path.parent.mkdir(parents=True, exist_ok=True)
        existing = read_text(sitecustomize_path)
        block = self._pip_hook_block()
        updated = replace_marked_block(existing, PIP_BEGIN_MARKER, PIP_END_MARKER, block)
        if existing == updated:
            return HookAction(
                target="pip",
                path=str(sitecustomize_path),
                status="unchanged",
                detail="SupplyScan pip hook already installed",
            )
        write_text(sitecustomize_path, updated)
        return HookAction(
            target="pip",
            path=str(sitecustomize_path),
            status="changed",
            detail=(
                "Installed SupplyScan interceptor into user sitecustomize.py after global permission denial"
                if fallback
                else "Installed SupplyScan interceptor into sitecustomize.py"
            ),
        )

    def _remove_pip_hook(self) -> HookAction:
        """Remove the pip sitecustomize hook."""

        try:
            paths = self._pip_removal_paths()
            changed_paths: list[str] = []
            inspected_paths: list[str] = []
            for sitecustomize_path in paths:
                inspected_paths.append(str(sitecustomize_path))
                existing = read_text(sitecustomize_path)
                updated = remove_marked_block(existing, PIP_BEGIN_MARKER, PIP_END_MARKER)
                if existing == updated:
                    continue
                write_text(sitecustomize_path, updated)
                changed_paths.append(str(sitecustomize_path))
            if not changed_paths:
                return HookAction(
                    target="pip",
                    path="; ".join(inspected_paths) if inspected_paths else "<unknown>",
                    status="unchanged",
                    detail="No SupplyScan pip hook was present",
                )
            return HookAction(
                target="pip",
                path="; ".join(changed_paths),
                status="changed",
                detail="Removed SupplyScan interceptor from sitecustomize.py",
            )
        except OSError as exc:
            return HookAction(target="pip", path="<unknown>", status="error", detail=str(exc))

    def _install_npm_hook(self) -> HookAction:
        """Install the npm preinstall hook into ~/.npmrc."""

        try:
            self.npmrc_path.parent.mkdir(parents=True, exist_ok=True)
            existing = read_text(self.npmrc_path)
            block = self._npm_hook_block()
            updated = replace_marked_block(existing, NPM_BEGIN_MARKER, NPM_END_MARKER, block)
            if existing == updated:
                return HookAction(
                    target="npm",
                    path=str(self.npmrc_path),
                    status="unchanged",
                    detail="SupplyScan npm hook already installed",
                )
            write_text(self.npmrc_path, updated)
            return HookAction(
                target="npm",
                path=str(self.npmrc_path),
                status="changed",
                detail="Installed SupplyScan preinstall hook into .npmrc",
            )
        except OSError as exc:
            return HookAction(target="npm", path=str(self.npmrc_path), status="error", detail=str(exc))

    def _remove_npm_hook(self) -> HookAction:
        """Remove the npm preinstall hook from ~/.npmrc."""

        try:
            existing = read_text(self.npmrc_path)
            updated = remove_marked_block(existing, NPM_BEGIN_MARKER, NPM_END_MARKER)
            if existing == updated:
                return HookAction(
                    target="npm",
                    path=str(self.npmrc_path),
                    status="unchanged",
                    detail="No SupplyScan npm hook was present",
                )
            write_text(self.npmrc_path, updated)
            return HookAction(
                target="npm",
                path=str(self.npmrc_path),
                status="changed",
                detail="Removed SupplyScan preinstall hook from .npmrc",
            )
        except OSError as exc:
            return HookAction(target="npm", path=str(self.npmrc_path), status="error", detail=str(exc))

    def _sitecustomize_path(self) -> Path:
        """Return the best writable site-packages sitecustomize.py path."""

        if self.site_packages is not None:
            return self.site_packages / "sitecustomize.py"
        candidates = candidate_site_packages()
        for candidate in candidates:
            if candidate.exists() and is_writable_directory(candidate):
                return candidate / "sitecustomize.py"
        preferred = candidates[0] if candidates else Path(sysconfig.get_paths()["purelib"])
        return preferred / "sitecustomize.py"

    def _user_sitecustomize_path(self) -> Path:
        """Return the active user's sitecustomize.py fallback path."""

        return Path(site.getusersitepackages()).expanduser() / "sitecustomize.py"

    def _pip_removal_paths(self) -> list[Path]:
        """Return all sitecustomize.py paths that may contain the SupplyScan pip hook."""

        candidates = [self._sitecustomize_path(), self._user_sitecustomize_path()]
        candidates.extend(candidate / "sitecustomize.py" for candidate in candidate_site_packages())
        deduped: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate.expanduser().resolve(strict=False)).lower()
            if key not in seen:
                seen.add(key)
                deduped.append(candidate.expanduser())
        return deduped

    def _pip_hook_block(self) -> str:
        """Render the marked pip hook block."""

        source_root = Path(__file__).resolve().parents[2]
        return "\n".join(
            [
                PIP_BEGIN_MARKER,
                "import os as _supplyscan_os",
                "import sys as _supplyscan_sys",
                f"_supplyscan_root = {str(source_root)!r}",
                "if _supplyscan_root not in _supplyscan_sys.path:",
                "    _supplyscan_sys.path.insert(0, _supplyscan_root)",
                "if not _supplyscan_os.environ.get('SUPPLYSCAN_DISABLE_HOOKS'):",
                "    try:",
                "        from supplyscan.hooks.sitecustomize import supplyscan_intercept_pip as _supplyscan_intercept_pip",
                "        _supplyscan_intercept_pip()",
                "    except SystemExit:",
                "        raise",
                "    except Exception as _supplyscan_exc:",
                "        _supplyscan_sys.stderr.write(f'SupplyScan hook error: {_supplyscan_exc}\\n')",
                PIP_END_MARKER,
                "",
            ]
        )

    def _npm_hook_block(self) -> str:
        """Render the marked npm hook block."""

        hook_path = Path(__file__).with_name("npm_hook.js")
        node_command = f"node {quote_npm_path(hook_path)}"
        return "\n".join(
            [
                NPM_BEGIN_MARKER,
                f"preinstall={node_command}",
                NPM_END_MARKER,
                "",
            ]
        )


def candidate_site_packages() -> list[Path]:
    """Return plausible site-packages directories for the running interpreter."""

    candidates: list[Path] = []
    for key in ("purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value:
            candidates.append(Path(value))
    try:
        candidates.extend(Path(path) for path in site.getsitepackages())
    except AttributeError:
        pass
    user_site = site.getusersitepackages()
    if user_site:
        candidates.append(Path(user_site))

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = str(candidate.expanduser())
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(candidate.expanduser())
    return deduped


def is_writable_directory(path: Path) -> bool:
    """Return whether a directory appears writable."""

    if not path.exists():
        return False
    return os.access(path, os.W_OK)


def read_text(path: Path) -> str:
    """Read a UTF-8 text file or return an empty string when absent."""

    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, text: str) -> None:
    """Write UTF-8 text to a path atomically enough for hook updates."""

    path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = path.with_suffix(path.suffix + ".supplyscan.bak")
    if path.exists() and not backup_path.exists():
        shutil.copy2(path, backup_path)
    path.write_text(text, encoding="utf-8", newline="\n")


def replace_marked_block(existing: str, begin_marker: str, end_marker: str, block: str) -> str:
    """Replace or append a marker-delimited block."""

    stripped = remove_marked_block(existing, begin_marker, end_marker).rstrip()
    if stripped:
        return stripped + "\n\n" + block
    return block


def remove_marked_block(existing: str, begin_marker: str, end_marker: str) -> str:
    """Remove a marker-delimited block from text."""

    begin = existing.find(begin_marker)
    if begin == -1:
        return existing
    end = existing.find(end_marker, begin)
    if end == -1:
        return existing
    end += len(end_marker)
    while end < len(existing) and existing[end] in {"\r", "\n"}:
        end += 1
    before = existing[:begin].rstrip()
    after = existing[end:].lstrip("\r\n")
    if before and after:
        return before + "\n\n" + after
    if before:
        return before + "\n"
    return after


def quote_npm_path(path: Path) -> str:
    """Quote a path for npmrc command values."""

    value = str(path)
    if " " in value:
        return f'"{value}"'
    return value
