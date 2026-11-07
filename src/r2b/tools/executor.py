from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from r2b.tools.models import (
    ExecutionResult,
    ExecutionStatus,
    ScriptLanguage,
    ToolName,
    TrajectoryEntry,
    ValidationResult,
)
from r2b.tools.validator import ScriptValidator


@dataclass
class ExecutionContext:

    script: str
    language: ScriptLanguage
    tool: ToolName
    timeout_ms: int = 30000
    validation: ValidationResult | None = None


@dataclass
class ExecutionOutput:

    validation: ValidationResult | None = None
    execution: ExecutionResult | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def to_trajectory_entry(
        self,
        intent: str,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        context_summary: str | None = None,
    ) -> TrajectoryEntry:
        return TrajectoryEntry(
            tool=tool,
            intent=intent,
            script=script,
            script_language=language,
            validation=self.validation,
            execution=self.execution,
            result=self.result,
            context_summary=context_summary,
        )


@runtime_checkable
class BridgeClient(Protocol):

    def is_connected(self) -> bool:
        ...

    def execute_script(self, script: str) -> dict[str, Any]:
        ...


class ToolExecutor:

    def execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int = 30000,
        intent: str = "",
    ) -> ExecutionOutput:
        validation = ScriptValidator.validate(script, language, tool)

        pre_check_result = self._pre_execute_check(validation)
        if pre_check_result is not None:
            return pre_check_result

        if not validation.valid:
            return ExecutionOutput(validation=validation, execution=None, result={})

        start_time = time.monotonic()
        try:
            status, stdout, stderr, exception, traceback = self._do_execute(
                script=script,
                language=language,
                tool=tool,
                timeout_ms=timeout_ms,
            )
        except NotImplementedError:
            raise
        except TimeoutError:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            execution = ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                duration_ms=duration_ms,
                stdout="",
                stderr="Execution timed out",
            )
            return ExecutionOutput(validation=validation, execution=execution)
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            execution = ExecutionResult(
                status=ExecutionStatus.ERROR,
                duration_ms=duration_ms,
                stdout="",
                stderr=str(e),
                exception=type(e).__name__,
            )
            return ExecutionOutput(validation=validation, execution=execution)

        duration_ms = int((time.monotonic() - start_time) * 1000)

        execution = ExecutionResult(
            status=status,
            duration_ms=duration_ms,
            stdout=stdout or "",
            stderr=stderr or "",
            exception=exception,
            traceback=traceback,
        )

        result = self._parse_output(stdout or "", stderr or "")

        return ExecutionOutput(validation=validation, execution=execution, result=result)

    def _pre_execute_check(
        self, validation: ValidationResult
    ) -> ExecutionOutput | None:
        return None

    def _do_execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int,
    ) -> tuple[ExecutionStatus, str | None, str | None, str | None, str | None]:
        raise NotImplementedError("Subclasses must implement _do_execute")

    def _parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {"raw_output": stdout, "raw_stderr": stderr}


class GhidraExecutor(ToolExecutor):

    def __init__(self, client: BridgeClient) -> None:
        self.client = client

    def _pre_execute_check(
        self, validation: ValidationResult
    ) -> ExecutionOutput | None:
        if not self.client.is_connected():
            execution = ExecutionResult(
                status=ExecutionStatus.CONNECTION_LOST,
                duration_ms=0,
                stdout="",
                stderr="Ghidra bridge is not connected",
            )
            return ExecutionOutput(validation=validation, execution=execution, result={})
        return None

    def _do_execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int,
    ) -> tuple[ExecutionStatus, str | None, str | None, str | None, str | None]:
        result = self.client.execute_script(script)
        error = result.get("error")
        if error:
            return ExecutionStatus.ERROR, result.get("output", ""), str(error), None, None
        return ExecutionStatus.SUCCESS, result.get("output", ""), "", None, None


class Radare2Executor(ToolExecutor):

    def __init__(self, r2pipe: Any = None) -> None:
        self._r2 = r2pipe

    @property
    def r2(self) -> Any:
        return self._r2

    @r2.setter
    def r2(self, value: Any) -> None:
        self._r2 = value

    def _do_execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int,
    ) -> tuple[ExecutionStatus, str | None, str | None, str | None, str | None]:
        if self._r2 is None:
            return (
                ExecutionStatus.ERROR,
                None,
                "r2pipe not initialized",
                "RuntimeError",
                None,
            )

        try:
            outputs = []
            for line in script.strip().split("\n"):
                line = line.strip()
                if line:
                    result = self._r2.cmd(line)
                    if result:
                        outputs.append(result)

            stdout = "\n".join(outputs)
            return ExecutionStatus.SUCCESS, stdout, "", None, None

        except Exception as e:
            return (
                ExecutionStatus.ERROR,
                None,
                str(e),
                type(e).__name__,
                None,
            )
