from __future__ import annotations

import platform
import subprocess
import sys

from pydantic import BaseModel, Field

DEFAULT_TIMEOUT_SECONDS = 3.0


class ToolStatus(BaseModel):
    name: str
    command: list[str]
    available: bool
    version: str | None = None
    error: str | None = None


class EnvironmentCheck(BaseModel):
    os_name: str
    os_release: str
    python_version: str
    tools: list[ToolStatus] = Field(default_factory=list)


TOOL_COMMANDS: tuple[tuple[str, list[str]], ...] = (
    ("nmap", ["nmap", "--version"]),
    ("curl", ["curl", "--version"]),
    ("tshark", ["tshark", "--version"]),
    ("wireshark", ["wireshark", "--version"]),
    ("vlc", ["vlc", "--version"]),
)


def _first_output_line(output: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def check_tool(command: list[str], *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ToolStatus:
    name = command[0]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return ToolStatus(name=name, command=command, available=False, error="not found")
    except subprocess.TimeoutExpired:
        return ToolStatus(name=name, command=command, available=False, error="timed out")
    except OSError as exc:
        return ToolStatus(name=name, command=command, available=False, error=str(exc))

    output = f"{result.stdout}\n{result.stderr}"
    version = _first_output_line(output)
    if result.returncode != 0:
        return ToolStatus(
            name=name,
            command=command,
            available=False,
            version=version,
            error=f"exit code {result.returncode}",
        )
    return ToolStatus(name=name, command=command, available=True, version=version)


def check_environment(*, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> EnvironmentCheck:
    return EnvironmentCheck(
        os_name=platform.system(),
        os_release=platform.release(),
        python_version=sys.version.split()[0],
        tools=[check_tool(command, timeout=timeout) for _, command in TOOL_COMMANDS],
    )
