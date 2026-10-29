from __future__ import annotations

import ast
import re
from typing import ClassVar

from r2b.tools.models import (
    ScriptLanguage,
    ToolName,
    ValidationError,
    ValidationResult,
)


class ScriptValidator:

    GHIDRA_FIXES: ClassVar[dict[str, tuple[str, str]]] = {
        r"\bgetFunctions\s*\(": (
            "currentProgram.getFunctionManager().getFunctions(True)",
            "Use currentProgram.getFunctionManager().getFunctions() instead of bare getFunctions()",
        ),
        r"\bgetBytes\s*\(": (
            "currentProgram.getMemory().getBytes(addr, bytearray(size))",
            "Use currentProgram.getMemory().getBytes() for reading memory",
        ),
        r"\bgetDataAt\s*\(": (
            "currentProgram.getListing().getDataAt(addr)",
            "Use currentProgram.getListing().getDataAt() for data access",
        ),
        r"\bgetSymbols\s*\(": (
            "currentProgram.getSymbolTable().getSymbols(name)",
            "Use currentProgram.getSymbolTable().getSymbols() for symbol lookup",
        ),
    }

    DANGEROUS_SHELL_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s*$", "rm -rf / is destructive"),
        (r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/\s*$", "rm -rf / is destructive"),
        (r"\bmkfs\.", "mkfs commands can destroy filesystems"),
        (r"\bdd\s+.*of=/dev/", "dd writing to device files is dangerous"),
        (r"\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)?777\s+/", "chmod -R 777 is insecure"),
    ]

    DANGEROUS_R2_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"^!", "Shell escape at start of command"),
        (r";\s*!", "Shell escape after semicolon"),
    ]

    DANGEROUS_PYTHON_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"\bos\.system\s*\(", "os.system() executes shell commands - use subprocess with shell=False"),
        (r"\bsubprocess\.[a-z]+\s*\([^)]*shell\s*=\s*True", "shell=True in subprocess is dangerous with untrusted input"),
        (r"\beval\s*\(", "eval() can execute arbitrary code"),
        (r"\bexec\s*\(", "exec() can execute arbitrary code"),
    ]

    @classmethod
    def validate(
        cls, script: str, language: ScriptLanguage, tool: ToolName
    ) -> ValidationResult:
        if language == ScriptLanguage.PYTHON:
            return cls._validate_python(script, tool)
        elif language == ScriptLanguage.R2:
            return cls._validate_r2(script)
        elif language == ScriptLanguage.SHELL:
            return cls._validate_shell(script, tool)
        else:
            return ValidationResult(
                valid=True,
                errors=[],
                warnings=[
                    ValidationError(
                        location="script",
                        message=f"Unknown language: {language}",
                        severity="warning",
                    )
                ],
            )

    @classmethod
    def _validate_python(cls, script: str, tool: ToolName) -> ValidationResult:
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        try:
            ast.parse(script)
        except SyntaxError as e:
            line_num = e.lineno or 1
            errors.append(
                ValidationError(
                    location=f"line {line_num}",
                    message=f"Syntax error: {e.msg}",
                    suggestion="Fix the Python syntax error",
                    severity="error",
                )
            )
            return ValidationResult(valid=False, errors=errors, warnings=warnings)

        warnings.extend(cls._check_dangerous_python(script))

        if tool == ToolName.GHIDRA:
            warnings.extend(cls._check_ghidra_patterns(script))
        elif tool == ToolName.ANGR:
            warnings.extend(cls._check_angr_patterns(script))

        return ValidationResult(valid=True, errors=errors, warnings=warnings)

    @classmethod
    def _validate_r2(cls, script: str) -> ValidationResult:
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        for i, line in enumerate(script.strip().split("\n"), start=1):
            line = line.strip()
            if not line:
                continue

            for pattern, description in cls.DANGEROUS_R2_PATTERNS:
                if re.search(pattern, line):
                    warnings.append(
                        ValidationError(
                            location=f"line {i}",
                            message=f"Shell escape detected: {description}",
                            suggestion="Avoid shell escapes in r2 scripts for security",
                            severity="warning",
                        )
                    )

        return ValidationResult(valid=True, errors=errors, warnings=warnings)

    @classmethod
    def _validate_shell(cls, script: str, tool: ToolName) -> ValidationResult:
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        for pattern, description in cls.DANGEROUS_SHELL_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE | re.MULTILINE):
                errors.append(
                    ValidationError(
                        location="script",
                        message=f"Dangerous command detected: {description}",
                        suggestion="Remove or modify the dangerous command",
                        severity="error",
                    )
                )

        valid = len(errors) == 0
        return ValidationResult(valid=valid, errors=errors, warnings=warnings)

    @classmethod
    def _check_ghidra_patterns(cls, script: str) -> list[ValidationError]:
        warnings: list[ValidationError] = []

        for pattern, (replacement, hint) in cls.GHIDRA_FIXES.items():
            matches = list(re.finditer(pattern, script))
            for match in matches:
                line_num = script[: match.start()].count("\n") + 1
                warnings.append(
                    ValidationError(
                        location=f"line {line_num}",
                        message=hint,
                        suggestion=f"Use: {replacement}",
                        severity="warning",
                    )
                )

        return warnings

    @classmethod
    def _check_angr_patterns(cls, script: str) -> list[ValidationError]:
        warnings: list[ValidationError] = []

        if "b.loader" in script and "proj.loader" not in script:
            warnings.append(
                ValidationError(
                    location="script",
                    message="'b.loader' is an older angr pattern",
                    suggestion="Use 'proj.loader' with modern angr",
                    severity="warning",
                )
            )

        return warnings

    @classmethod
    def _check_dangerous_python(cls, script: str) -> list[ValidationError]:
        warnings: list[ValidationError] = []

        for pattern, description in cls.DANGEROUS_PYTHON_PATTERNS:
            matches = list(re.finditer(pattern, script))
            for match in matches:
                line_num = script[: match.start()].count("\n") + 1
                warnings.append(
                    ValidationError(
                        location=f"line {line_num}",
                        message=description,
                        suggestion="Consider using safer alternatives",
                        severity="warning",
                    )
                )

        return warnings
