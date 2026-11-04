"""AST-based defensive integrity checks for Python source trees."""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

_SECRET_NAME_PATTERN = re.compile(
    r"(?:(?:API|ACCESS|AUTH|PRIVATE|CLIENT)[_-]?(?:KEY|TOKEN|SECRET)|"
    r"(?:PASSWORD|PASSWD|DB[_-]?URL))\Z",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERN = re.compile(
    r"(?:sk|pk|ghp|xox[baprs])[-_][A-Za-z0-9_-]{16,}",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SecurityFinding:
    """One static integrity finding with a stable rule identifier."""

    path: str
    line: int
    rule: str
    message: str
    severity: str = "high"

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def _target_names(target: ast.expr) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)


class _IntegrityVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SecurityFinding] = []
        self.dynamic_call_aliases = {"eval", "exec"}
        self.shell_call_aliases = {"system"}
        self.subprocess_call_aliases = {"run"}

    def _add(self, node: ast.AST, rule: str, message: str) -> None:
        self.findings.append(
            SecurityFinding(
                path=self.path,
                line=getattr(node, "lineno", 1),
                rule=rule,
                message=message,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module = alias.name.split(".", 1)[0]
            local_name = alias.asname or module
            if module in {"pickle", "marshal"}:
                self._add(
                    node,
                    "SEC-STATIC-UNSAFE-IMPORT",
                    "Unsafe object deserialization import is prohibited.",
                )
            if module == "os":
                self.shell_modules = getattr(self, "shell_modules", {"os"})
                self.shell_modules.add(local_name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = (node.module or "").split(".", 1)[0]
        if module in {"pickle", "marshal"}:
            self._add(
                node,
                "SEC-STATIC-UNSAFE-IMPORT",
                "Unsafe object deserialization import is prohibited.",
            )
        for alias in node.names:
            local_name = alias.asname or alias.name
            if module == "builtins" and alias.name in {"eval", "exec"}:
                self.dynamic_call_aliases.add(local_name)
            if module == "os" and alias.name == "system":
                self.shell_call_aliases.add(local_name)
            if module == "subprocess" and alias.name == "run":
                self.subprocess_call_aliases.add(local_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function_name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr if isinstance(node.func, ast.Attribute) else ""
        )
        if function_name in self.dynamic_call_aliases:
            self._add(
                node,
                "SEC-STATIC-DYNAMIC-EVAL",
                "Dynamic code execution is prohibited.",
            )
        is_shell_attribute = isinstance(node.func, ast.Attribute) and (
            getattr(self, "shell_modules", {"os"}).__contains__(
                node.func.value.id
            )
            if isinstance(node.func.value, ast.Name)
            else False
        )
        if function_name in self.shell_call_aliases or (
            function_name == "system" and is_shell_attribute
        ):
            self._add(
                node,
                "SEC-STATIC-OS-SHELL",
                "OS shell-string execution is prohibited.",
            )
        if function_name in self.subprocess_call_aliases:
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    self._add(
                        node,
                        "SEC-STATIC-SHELL-TRUE",
                        "Subprocess shell execution is prohibited.",
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for name in _target_names(target):
                self._check_secret_literal(name, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        for name in _target_names(node.target):
            if node.value is not None:
                self._check_secret_literal(name, node.value, node)
        self.generic_visit(node)

    def _check_secret_literal(
        self,
        name: str,
        value: ast.expr,
        node: ast.AST,
    ) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(
            value.value, str
        ):
            return
        if _SECRET_NAME_PATTERN.fullmatch(
            name
        ) or _SECRET_VALUE_PATTERN.search(value.value):
            self._add(
                node,
                "SEC-STATIC-HARDCODED-SECRET",
                "A secret-like literal must not be committed to source.",
            )


def scan_source(source: str, path: str = "<memory>") -> list[SecurityFinding]:
    """Inspect Python source without importing or executing it."""
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return [
            SecurityFinding(
                path=path,
                line=1,
                rule="SEC-STATIC-SYNTAX",
                message="Source could not be parsed for integrity checks.",
                severity="medium",
            )
        ]
    visitor = _IntegrityVisitor(path)
    visitor.visit(tree)
    return visitor.findings


def scan_project(
    root: str | Path,
    *,
    excluded_names: frozenset[str] = frozenset(),
) -> list[SecurityFinding]:
    """Scan Python source files without importing or executing project code."""
    project_root = Path(root).resolve()
    findings: list[SecurityFinding] = []
    for source_path in sorted(project_root.rglob("*.py")):
        if any(
            part in {".git", "__pycache__", ".venv", "venv"}
            for part in source_path.parts
        ):
            continue
        if source_path.name in excluded_names:
            continue
        try:
            source = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            findings.append(
                SecurityFinding(
                    path=str(source_path.relative_to(project_root)),
                    line=1,
                    rule="SEC-STATIC-READ",
                    message="Source file could not be read for integrity checks.",
                    severity="medium",
                )
            )
            continue
        findings.extend(
            scan_source(source, str(source_path.relative_to(project_root)))
        )
    return findings


__all__ = ["SecurityFinding", "scan_project", "scan_source"]
