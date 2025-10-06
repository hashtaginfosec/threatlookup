"""Data models for threat analysis using Pydantic v2."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Threat level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskScore(BaseModel):
    """Risk score model with detailed breakdown."""
    overall_score: float = Field(ge=0.0, le=10.0, description="Overall risk score (0-10)")
    threat_level: ThreatLevel
    registration_age_score: float = Field(ge=0.0, le=10.0)
    country_risk_score: float = Field(ge=0.0, le=10.0)
    randomness_score: float = Field(ge=0.0, le=10.0)
    otx_score: float = Field(ge=0.0, le=10.0, default=0.0)
    virustotal_score: float = Field(ge=0.0, le=10.0, default=0.0)
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the assessment")


class DomainAnalysis(BaseModel):
    """Domain analysis results."""
    domain: str
    registration_date: Optional[datetime] = None
    country: Optional[str] = None
    registrar: Optional[str] = None
    days_since_registration: Optional[int] = None
    is_randomized: bool = False
    risk_score: RiskScore
    remediation_steps: list[str] = Field(default_factory=list)
    otx_data: Optional[dict] = None
    virustotal_data: Optional[dict] = None
    claude_analysis: Optional[dict] = None


class WhoisData(BaseModel):
    """WHOIS data model."""
    domain: str
    registration_date: Optional[datetime] = None
    country: Optional[str] = None
    registrar: Optional[str] = None
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
