"""
Zelis Security Agents - Data Models
Pydantic models for structured findings, threat models, and agent state.
"""
from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTO_APPROVED = "auto_approved"


class ReviewRecommendation(str, Enum):
    PASS = "pass"
    CONDITIONAL_PASS = "conditional_pass"
    ESCALATE = "escalate"


# ─── Architecture Review Models ─────────────────────────────────────────────

class Threat(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: str  # STRIDE category
    component: str
    description: str
    likelihood: str  # low/medium/high
    impact: str      # low/medium/high
    severity: Severity
    mitigations: list[str]
    framework_reference: str  # e.g., "OWASP ASVS V2.1.1"


class PolicyViolation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    policy_name: str
    control_id: str
    description: str
    severity: Severity
    component: str
    remediation: str


class Component(BaseModel):
    name: str
    type: str  # service, database, API gateway, etc.
    trust_zone: str
    data_classification: str
    external_dependencies: list[str] = []
    authentication_method: Optional[str] = None
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False


class ArchitectureReviewFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    severity: Severity
    category: str
    component: str
    description: str
    rationale: str
    remediation: str
    framework_control: str
    needs_human_review: bool = False


class ArchitectureReviewReport(BaseModel):
    review_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    design_name: str
    components: list[Component] = []
    threats: list[Threat] = []
    policy_violations: list[PolicyViolation] = []
    findings: list[ArchitectureReviewFinding] = []
    recommendation: ReviewRecommendation = ReviewRecommendation.CONDITIONAL_PASS
    summary: str = ""
    assumptions: list[str] = []
    questions_asked: list[str] = []
    human_review_required: bool = False
    reviewer_notes: Optional[str] = None


# ─── Penetration Testing Models ──────────────────────────────────────────────

class ScopeDefinition(BaseModel):
    target_name: str
    in_scope_targets: list[str]  # IPs, domains, URLs
    out_of_scope: list[str]
    allowed_techniques: list[str]
    test_window_start: Optional[str] = None
    test_window_end: Optional[str] = None
    rate_limit_rps: int = 10
    authorized_by: str
    authorization_token: str = Field(default_factory=lambda: str(uuid.uuid4()))


class ReconResult(BaseModel):
    target: str
    open_ports: list[int] = []
    services: dict[str, str] = {}  # port -> service/version
    technologies: list[str] = []
    endpoints: list[str] = []
    certificates: list[dict[str, Any]] = []


class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    cve_ids: list[str] = []
    severity: Severity
    cvss_score: float = 0.0
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    description: str
    evidence: str
    reproduction_steps: list[str]
    mitre_technique: Optional[str] = None  # e.g., "T1190"
    remediation: str
    validated: bool = False
    exploit_type: str = "safe_poc"  # safe_poc | intrusive | destructive


class AttackPath(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    steps: list[str]
    techniques: list[str]  # MITRE ATT&CK technique IDs
    impact: str
    likelihood: str
    severity: Severity


class HumanApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    action_type: str
    description: str
    target: str
    risk_level: Severity
    justification: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    notes: Optional[str] = None


class AuditLogEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    agent: str
    action: str
    target: Optional[str] = None
    parameters: dict[str, Any] = {}
    result: Optional[str] = None
    approved_by: Optional[str] = None


class PentestReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    scope: Optional[ScopeDefinition] = None
    recon_results: list[ReconResult] = []
    vulnerabilities: list[Vulnerability] = []
    attack_paths: list[AttackPath] = []
    approval_requests: list[HumanApprovalRequest] = []
    audit_log: list[AuditLogEntry] = []
    summary: str = ""
    risk_rating: Severity = Severity.MEDIUM
    executive_summary: str = ""
