from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    positive = "Positive"
    info = "Info"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class DiscoveredHost(BaseModel):
    ip: str
    hostname: str | None = None
    mac_oui: str | None = None
    vendor: str | None = None
    latency_ms: float | None = None
    notes: list[str] = Field(default_factory=list)


class OpenPort(BaseModel):
    port: int
    proto: str = "tcp"
    service: str | None = None
    meaning: str | None = None


class Finding(BaseModel):
    title: str
    severity: Severity
    evidence: str
    explanation: str
    remediation: str | None = None


class SessionResult(BaseModel):
    scope: str
    authorized: bool
    hosts: list[DiscoveredHost] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    raw_dir: Path | None = None
