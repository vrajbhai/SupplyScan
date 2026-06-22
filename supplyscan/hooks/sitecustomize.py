"""Injected Python hook that intercepts package installs before pip proceeds."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from supplyscan.models import ScanTarget


console = Console(stderr=True)


def supplyscan_intercept_pip() -> None:
    """Intercept pip-driven execution and block malicious installs."""

    if should_skip_hooks():
        return
    targets = resolve_install_targets()
    if not targets:
        return
    for target in targets:
        result = run_supplyscan_cli(target)
        if result.returncode != 0:
            render_block(target, result)
            raise SystemExit(1)


def run_supplyscan_cli(target: ScanTarget) -> subprocess.CompletedProcess[str]:
    """Run the SupplyScan CLI in a subprocess with hooks disabled."""

    command = [
        sys.executable,
        "-m",
        "supplyscan.cli.main",
        "check",
        target.name,
        "--source",
        target.source or "pip",
    ]
    if target.version:
        command.extend(["--version", target.version])
    env = dict(os.environ)
    env["SUPPLYSCAN_DISABLE_HOOKS"] = "1"
    return subprocess.run(
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def should_skip_hooks() -> bool:
    """Return whether hook execution should be skipped to avoid recursion."""

    if os.environ.get("SUPPLYSCAN_DISABLE_HOOKS"):
        return True
    executable = Path(sys.argv[0]).name.lower() if sys.argv else ""
    return executable in {"supplyscan", "supplyscan.exe"}


def resolve_install_targets() -> list[ScanTarget]:
    """Resolve packages currently being installed from pip arguments."""

    targets: list[ScanTarget] = []
    args = list(sys.argv[1:])
    if "install" not in args and "wheel" not in args and "download" not in args:
        return []
    iterator = iter(range(len(args)))
    for index in iterator:
        value = args[index]
        if value in {"install", "wheel", "download"}:
            continue
        if value in {"-r", "--requirement"} and index + 1 < len(args):
            targets.extend(parse_requirements_file(Path(args[index + 1])))
            next(iterator, None)
            continue
        if value.startswith("-"):
            continue
        parsed = parse_package_spec(value)
        if parsed is not None:
            targets.append(parsed)
    return targets


def parse_requirements_file(path: Path) -> list[ScanTarget]:
    """Parse simple package specs from a requirements file."""

    if not path.exists() or not path.is_file():
        return []
    targets: list[ScanTarget] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        parsed = parse_package_spec(line)
        if parsed is not None:
            targets.append(parsed)
    return targets


def parse_package_spec(spec: str) -> ScanTarget | None:
    """Parse a pip package spec into a scan target."""

    cleaned = spec.strip()
    if not cleaned or cleaned.startswith("-"):
        return None
    if "==" in cleaned:
        name, version = cleaned.split("==", 1)
        return ScanTarget(name=name.strip(), version=version.strip() or None, source="pip")
    if "@" in cleaned and cleaned.count("@") == 1:
        name = cleaned.split("@", 1)[0].strip()
        return ScanTarget(name=name, version=None, source="pip") if name else None
    for operator in (">=", "<=", "~=", "!=", ">", "<"):
        if operator in cleaned:
            name = cleaned.split(operator, 1)[0].strip()
            return ScanTarget(name=name, version=None, source="pip") if name else None
    return ScanTarget(name=cleaned, version=None, source="pip")


def render_block(target: ScanTarget, result: subprocess.CompletedProcess[str]) -> None:
    """Render a rich error panel for blocked installs."""

    output = (result.stdout + "\n" + result.stderr).strip()
    details = [
        f"Package: {target.name}",
        f"Version: {target.version or 'unspecified'}",
        f"Exit code: {result.returncode}",
        "",
        "SupplyScan output:",
        output or "SupplyScan returned a blocking result with no output.",
    ]
    details.append("")
    details.append("Install BLOCKED. Run with --force to override.")
    console.print(
        Panel.fit(
            "\n".join(details),
            title="SupplyScan blocked install",
            border_style="red",
        )
    )
