"""libCST-based Python static analysis detector."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from supplyscan.detectors.common import (
    ResultBuilder,
    collect_source_files,
    evidence,
    is_install_context,
    max_severity,
    resolve_source_path,
)
from supplyscan.models import DetectorResult, EvidenceItem, ScanTarget, Severity

try:
    import libcst as cst
    from libcst.metadata import MetadataWrapper, PositionProvider
except ImportError:
    cst = None
    MetadataWrapper = None
    PositionProvider = None


class AstFinding(BaseModel):
    """A finding emitted by libCST analysis."""

    model_config = ConfigDict(frozen=True)

    finding: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    severity: Severity
    evidence: str = Field(min_length=1)


if cst is not None:

    class PythonSecurityVisitor(cst.CSTVisitor):
        """libCST visitor that records security-relevant Python patterns."""

        METADATA_DEPENDENCIES = (PositionProvider,)

        def __init__(self, relative_path: str) -> None:
            """Create a visitor for one Python file."""

            self.relative_path = relative_path
            self.findings: list[AstFinding] = []

        def visit_Call(self, node: Any) -> None:
            """Inspect calls for dynamic execution, shell usage, and unsafe writes."""

            name = qualified_name(node.func)
            line_number = self._line_number(node)
            install_context = is_install_context(self.relative_path)
            if name in {"eval", "exec"} and node.args:
                first_arg = node.args[0].value
                if not is_static_literal(first_arg):
                    self.findings.append(
                        AstFinding(
                            finding=f"Dynamic {name}() execution",
                            relative_path=self.relative_path,
                            line_number=line_number,
                            severity=Severity.HIGH if install_context else Severity.MEDIUM,
                            evidence=f"{name}() called with non-literal input",
                        )
                    )
            if name in {
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
                "subprocess.run",
            } and has_shell_true(node):
                self.findings.append(
                    AstFinding(
                        finding="subprocess shell=True in Python source",
                        relative_path=self.relative_path,
                        line_number=line_number,
                        severity=Severity.HIGH if install_context else Severity.MEDIUM,
                        evidence=f"{name}(..., shell=True)",
                    )
                )
            if name in {"open", "pathlib.Path.open"} and writes_sensitive_path(node):
                self.findings.append(
                    AstFinding(
                        finding="File write targets a sensitive path outside the package",
                        relative_path=self.relative_path,
                        line_number=line_number,
                        severity=Severity.HIGH,
                        evidence="open() writes to /tmp, /etc, home, ssh, aws, or npm credentials",
                    )
                )

        def visit_Attribute(self, node: Any) -> None:
            """Inspect attribute accesses for credential harvesting patterns."""

            name = qualified_name(node)
            if name in {"os.environ", "os.getenv"}:
                line_number = self._line_number(node)
                self.findings.append(
                    AstFinding(
                        finding="Environment variable access in package code",
                        relative_path=self.relative_path,
                        line_number=line_number,
                        severity=Severity.LOW,
                        evidence=name,
                    )
                )

        def _line_number(self, node: Any) -> int:
            """Return the source line for a CST node."""

            position = self.get_metadata(PositionProvider, node)
            return int(position.start.line)

else:

    class PythonSecurityVisitor:
        """Unavailable visitor used when libCST is not installed."""

        def __init__(self, relative_path: str) -> None:
            """Create an unavailable visitor."""

            self.relative_path = relative_path
            self.findings: list[AstFinding] = []


class AstDetector:
    """Detect dangerous Python constructs using libCST."""

    def __init__(self) -> None:
        """Create an AST detector."""

        self.result_builder = ResultBuilder(detector_name="ast")

    async def scan(self, target: ScanTarget) -> DetectorResult:
        """Scan Python files with libCST static analysis."""

        root = resolve_source_path(target)
        if root is None:
            return self.result_builder.clean([evidence("scope", "no local source available")])
        if cst is None or MetadataWrapper is None:
            return self.result_builder.clean([evidence("dependency", "libCST is not installed")])

        findings: list[str] = []
        evidence_items: list[EvidenceItem] = []
        severity = Severity.INFO
        for source_file in await collect_source_files(root, suffixes={".py"}):
            try:
                module = cst.parse_module(source_file.text)
                wrapper = MetadataWrapper(module)
                visitor = PythonSecurityVisitor(source_file.relative_path)
                wrapper.visit(visitor)
            except cst.ParserSyntaxError as exc:
                evidence_items.append(evidence(source_file.relative_path, f"parse error: {exc}"))
                continue
            for item in visitor.findings:
                findings.append(f"{item.finding} in {item.relative_path} line {item.line_number}")
                evidence_items.append(evidence(f"{item.relative_path}:{item.line_number}", item.evidence))
                severity = max_severity(severity, item.severity)

        return self.result_builder.build(findings, evidence_items, severity)


def qualified_name(node: Any) -> str:
    """Return a dotted name for a libCST expression."""

    if cst is None:
        return ""
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        base = qualified_name(node.value)
        if not base:
            return node.attr.value
        return f"{base}.{node.attr.value}"
    return ""


def is_static_literal(node: Any) -> bool:
    """Return whether a libCST expression is a static literal."""

    if cst is None:
        return False
    if isinstance(node, (cst.SimpleString, cst.Integer, cst.Float, cst.Imaginary)):
        return True
    if isinstance(node, cst.Name) and node.value in {"True", "False", "None"}:
        return True
    if isinstance(node, (cst.List, cst.Tuple, cst.Set)):
        return all(is_static_literal(element.value) for element in node.elements)
    if isinstance(node, cst.Dict):
        return all(
            element.key is not None
            and is_static_literal(element.key)
            and is_static_literal(element.value)
            for element in node.elements
            if isinstance(element, cst.DictElement)
        )
    return False


def has_shell_true(node: Any) -> bool:
    """Return whether a call has shell=True."""

    if cst is None:
        return False
    for arg in node.args:
        if arg.keyword is None or arg.keyword.value != "shell":
            continue
        if isinstance(arg.value, cst.Name) and arg.value.value == "True":
            return True
    return False


def writes_sensitive_path(node: Any) -> bool:
    """Return whether an open-like call writes to a sensitive absolute path."""

    if cst is None or not node.args:
        return False
    path_arg = node.args[0].value
    mode_arg = node.args[1].value if len(node.args) > 1 else None
    path_value = literal_string_value(path_arg)
    mode_value = literal_string_value(mode_arg) if mode_arg is not None else ""
    if path_value is None:
        return False
    write_mode = any(flag in mode_value for flag in {"w", "a", "+"})
    sensitive = any(
        marker in path_value
        for marker in {"/tmp/", "/etc/", "/var/", "~", ".ssh", ".aws", ".npmrc", "id_rsa"}
    )
    return write_mode and sensitive


def literal_string_value(node: Any) -> str | None:
    """Return a decoded simple string literal value when possible."""

    if cst is None or node is None or not isinstance(node, cst.SimpleString):
        return None
    try:
        value = node.evaluated_value
    except ValueError:
        return None
    return value if isinstance(value, str) else None
