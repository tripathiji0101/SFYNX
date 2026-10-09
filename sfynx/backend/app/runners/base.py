"""
SFYNX Base Runner — abstract adapter for security tools.

Every security tool integration must subclass BaseRunner and implement:
- _build_command(): construct the CLI arguments
- _parse_output(): convert raw output to Finding objects

This enforces a consistent interface:
validate → build command → execute → capture → parse → normalize → return
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.schemas.scan import TaskResult, TaskStatus

if TYPE_CHECKING:
    from app.schemas.finding import Finding

logger = logging.getLogger("sfynx.runners")


class RunnerError(Exception):
    """Raised when a runner encounters a fatal error."""


class BaseRunner(ABC):
    """
    Abstract base class for security tool adapters.

    Subclasses only need to implement:
    - tool_name: the canonical name of the tool
    - _build_command(): how to construct CLI args
    - _parse_output(): how to parse raw output into Findings
    """

    tool_name: str = "unknown"
    default_timeout: int = 120

    def __init__(self, binary_path: str | None = None, timeout: int | None = None) -> None:
        self.binary_path = binary_path or self.tool_name
        self.timeout = timeout or self.default_timeout

    def _find_binary(self) -> str:
        """Locate the tool binary on PATH. Raises RunnerError if not found."""
        found = shutil.which(self.binary_path)
        if not found:
            raise RunnerError(
                f"Tool '{self.binary_path}' not found on PATH. "
                f"Install it or set the correct binary path."
            )
        return found

    @abstractmethod
    def _build_command(
        self, target: str, output_file: Path, **kwargs: Any
    ) -> list[str]:
        """
        Build the subprocess argument array for the tool.

        MUST return a list[str] — NEVER a shell string.
        """
        ...

    @abstractmethod
    def _parse_output(
        self, raw_output: str, target: str, scan_id: str
    ) -> list[Finding]:
        """Parse the tool's raw output into normalized Finding objects."""
        ...

    async def run(
        self, target: str, scan_id: str, **kwargs: Any
    ) -> tuple[TaskResult, list[Finding]]:
        """
        Execute the security tool and return normalized results.

        This is the main entry point. It handles:
        1. Binary validation
        2. Temp file management
        3. Subprocess execution with timeout
        4. stdout/stderr capture
        5. Exit code handling
        6. Output parsing
        7. Error handling
        """
        started_at = datetime.now(UTC)

        # Validate binary exists
        try:
            binary = self._find_binary()
        except RunnerError as e:
            return (
                TaskResult(
                    tool=self.tool_name,
                    status=TaskStatus.FAILED,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    error=str(e),
                ),
                [],
            )

        # Create temp directory for output files
        with tempfile.TemporaryDirectory(prefix=f"sfynx_{self.tool_name}_") as tmpdir:
            output_file = Path(tmpdir) / "output.json"

            # Build command — safe argument array, never shell string
            try:
                cmd = self._build_command(target, output_file, **kwargs)
            except Exception as e:
                return (
                    TaskResult(
                        tool=self.tool_name,
                        status=TaskStatus.FAILED,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        error=f"Failed to build command: {e}",
                    ),
                    [],
                )

            # Replace tool name with resolved binary path
            cmd[0] = binary

            logger.info(
                "Running %s: scan_id=%s target=%s timeout=%ds",
                self.tool_name,
                scan_id,
                target,
                self.timeout,
            )

            # Execute subprocess
            stdout_data = ""
            stderr_data = ""
            exit_code = -1
            process: asyncio.subprocess.Process | None = None
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
                stdout_data = stdout_bytes.decode("utf-8", errors="replace")
                stderr_data = stderr_bytes.decode("utf-8", errors="replace")
                exit_code = process.returncode if process.returncode is not None else 0

            except TimeoutError:
                logger.warning(
                    "%s timed out after %ds: scan_id=%s",
                    self.tool_name,
                    self.timeout,
                    scan_id,
                )
                if process:
                    try:
                        process.kill()
                        await process.wait()
                    except ProcessLookupError:
                        pass
                return (
                    TaskResult(
                        tool=self.tool_name,
                        status=TaskStatus.FAILED,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        exit_code=-1,
                        error=f"Timed out after {self.timeout}s",
                    ),
                    [],
                )
            except Exception as e:
                logger.error(
                    "%s execution failed: scan_id=%s error=%s",
                    self.tool_name,
                    scan_id,
                    e,
                )
                return (
                    TaskResult(
                        tool=self.tool_name,
                        status=TaskStatus.FAILED,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        error=str(e),
                    ),
                    [],
                )

            # Read output file if it exists, otherwise use stdout
            raw_output = ""
            if output_file.exists():
                raw_output = output_file.read_text(encoding="utf-8", errors="replace")
            elif stdout_data:
                raw_output = stdout_data

            logger.info(
                "%s finished: scan_id=%s exit_code=%d output_size=%d stderr_size=%d",
                self.tool_name,
                scan_id,
                exit_code,
                len(raw_output),
                len(stderr_data),
            )

            # Parse output into findings
            findings: list[Finding] = []
            try:
                if raw_output.strip():
                    findings = self._parse_output(raw_output, target, scan_id)
            except Exception as e:
                logger.error(
                    "%s output parsing failed: scan_id=%s error=%s",
                    self.tool_name,
                    scan_id,
                    e,
                )
                return (
                    TaskResult(
                        tool=self.tool_name,
                        status=TaskStatus.FAILED,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        exit_code=exit_code,
                        error=f"Output parsing failed: {e}",
                    ),
                    [],
                )

            finished_at = datetime.now(UTC)
            status = TaskStatus.COMPLETED if exit_code == 0 else TaskStatus.FAILED

            return (
                TaskResult(
                    tool=self.tool_name,
                    status=status,
                    started_at=started_at,
                    finished_at=finished_at,
                    exit_code=exit_code,
                    error=stderr_data if exit_code != 0 else "",
                    finding_count=len(findings),
                ),
                findings,
            )
