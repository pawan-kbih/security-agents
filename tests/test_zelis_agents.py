"""
Zelis Security Agents - Comprehensive Test Suite
Tests 100% of the assessment requirements:
- Use Case 1: Architecture Review Agent, STRIDE, policy compliance, OPA, IaC scanning, DFD, clarifying questions, escalation
- Use Case 2: Scope gateway, Kill switch, rate limits, test window, approvals, safe PoC, retest, credential purge, audit log
- API Endpoints: FastAPI route validation for both agents and all guardrails
"""
import asyncio
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from src.agents.arch_review_agent import run_arch_review
from src.agents.pentest_agent import run_pentest
from src.api.main import app
from src.tools.pentest_tools import (
    validate_scope_and_authorization,
    run_port_scan,
    enumerate_web_endpoints,
    run_vulnerability_scanner,
    validate_proof_of_concept,
    request_human_approval,
    map_attack_paths,
    retest_vulnerability,
    generate_pentest_report,
    purge_engagement_data,
    activate_kill_switch,
    deactivate_kill_switch,
    get_audit_log,
    get_approval_requests,
    get_findings_db,
    set_active_scope,
    _check_scope,
    _check_kill_switch,
    _check_test_window,
    _check_rate_limit,
)
from src.tools.arch_review_tools import (
    parse_design_document,
    ask_clarifying_questions,
    generate_data_flow_diagram,
    parse_iac_config,
    run_policy_as_code_check,
    run_stride_threat_model,
    check_policy_compliance,
    retrieve_framework_control,
    rate_and_prioritize_findings,
    generate_architecture_report,
    ARCH_REVIEW_TOOLS,
)


@pytest.fixture(autouse=True)
def reset_state():
    """Ensure clean state before each test."""
    deactivate_kill_switch()
    set_active_scope({
        "engagement_name": "Test Scope",
        "in_scope_targets": ["192.168.1.10", "dev.zelis.internal", "10.0.0.0/24"],
        "out_of_scope": ["prod.zelis.com", "payment.zelis.com"],
        "rate_limit_rps": 50,
        "test_window_start": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
        "test_window_end": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat() + "Z",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# USE CASE 1 TESTS: Security Architecture Review Agent
# ═══════════════════════════════════════════════════════════════════════════════

def test_run_arch_review_returns_fallback_findings_when_llm_is_unavailable(monkeypatch):
    async def _run():
        return await run_arch_review(
            "Public API gateway connects to Postgres over plain HTTP and stores secrets in environment files.",
            stream_callback=None,
        )

    async def _fake_llm_invoke(*args, **kwargs):
        raise RuntimeError("API key missing")

    monkeypatch.setattr("src.agents.arch_review_agent.ChatOpenAI.invoke", _fake_llm_invoke)
    report = asyncio.run(_run())
    assert report["findings"]
    assert report["recommendation"] in {"conditional_pass", "escalate"}
    assert report["summary"]


def test_run_pentest_creates_pending_approval_when_scope_is_admin_facing(monkeypatch):
    async def _run():
        return await run_pentest(
            {
                "target_name": "Admin Gateway Validation",
                "in_scope_targets": ["admin-gateway.internal.zelis.example.com"],
                "out_of_scope": [],
                "allowed_techniques": ["passive_recon", "port_scan", "web_enum", "safe_poc"],
                "authorized_by": "Ops Lead",
                "test_window_start": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                "test_window_end": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "rate_limit_rps": 10,
            },
            stream_callback=None,
        )

    async def _fake_llm_invoke(*args, **kwargs):
        raise RuntimeError("API key missing")

    monkeypatch.setattr("src.agents.pentest_agent.ChatOpenAI.invoke", _fake_llm_invoke)
    initial = len(get_approval_requests())
    report = asyncio.run(_run())
    approvals = get_approval_requests()
    assert len(approvals) >= initial + 1
    assert any(a.get("status") == "pending" and "admin" in (a.get("action_type") or "").lower() for a in approvals)
    assert report["approval_requests"]


def test_run_arch_review_creates_pending_approval_when_recommendation_is_escalate(monkeypatch):
    async def _run():
        return await run_arch_review(
            "Public internet gateway connects directly to production RDS with plaintext credentials and no mTLS.",
            stream_callback=None,
        )

    async def _fake_llm_invoke(*args, **kwargs):
        raise RuntimeError("API key missing")

    monkeypatch.setattr("src.agents.arch_review_agent.ChatOpenAI.invoke", _fake_llm_invoke)
    initial = len(get_approval_requests())
    report = asyncio.run(_run())
    approvals = get_approval_requests()
    assert len(approvals) >= initial + 1
    assert any(a.get("status") == "pending" and "architecture" in (a.get("action_type") or "").lower() for a in approvals)
    assert report["human_review_required"] is True


def test_parse_design_document_extracts_components():
    design = """
    Architecture:
    - Service A: API Gateway exposed to public on port 443
    - Service B: Payment Service in private subnet
    - Service C: User Database with PII and PHI records
    - Service D: Redis cache storing unencrypted session tokens
    """
    result = parse_design_document.invoke({"design_text": design})
    assert result["component_count"] >= 3
    assert result["has_pii"] is True
    assert result["has_phi"] is True
    assert "clarifying_questions" in result
    assert isinstance(result["components"], list)


def test_clarifying_questions_tool():
    questions = json.dumps([
        "Where are secrets stored for the database?",
        "How do services authenticate to each other?",
        "What encryption algorithm is used at rest?",
    ])
    result = ask_clarifying_questions.invoke({"questions_json": questions, "context": "Payment v2"})
    assert result["questions_asked"] == 3
    assert result["all_answered"] is True
    assert len(result["answers"]) == 3


def test_generate_data_flow_diagram_mermaid():
    components = json.dumps([
        {"name": "API Gateway", "type": "gateway", "trust_zone": "DMZ", "data_classification": "Public"},
        {"name": "Payment API", "type": "service", "trust_zone": "Trusted Zone", "data_classification": "Confidential"},
        {"name": "User DB", "type": "database", "trust_zone": "Trusted Zone", "data_classification": "Restricted/PII"},
    ])
    result = generate_data_flow_diagram.invoke({"components_json": components, "design_name": "Payment Pipeline"})
    assert "mermaid_diagram" in result
    assert "graph TD" in result["mermaid_diagram"]
    assert "Payment API" in result["mermaid_diagram"]
    assert result["component_count"] == 3


def test_parse_iac_terraform_misconfigurations():
    tf_iac = """
    resource "aws_db_instance" "db" {
      publicly_accessible = true
      encrypted = false
    }
    resource "aws_s3_bucket" "b" {
      public_access_block = false
    }
    """
    result = parse_iac_config.invoke({"iac_text": tf_iac, "iac_type": "terraform"})
    assert result["total_issues"] >= 3
    assert result["critical"] >= 1
    assert any("RDS instance is publicly accessible" in i["description"] for i in result["issues"])


def test_parse_iac_kubernetes_misconfigurations():
    k8s_yaml = """
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: app
        securityContext:
          privileged: true
          runAsRoot: true
    """
    result = parse_iac_config.invoke({"iac_text": k8s_yaml, "iac_type": "kubernetes"})
    assert result["total_issues"] >= 2
    assert result["critical"] >= 1


def test_run_policy_as_code_check_opa():
    insecure_design = "External service connects via http:// with no auth and stores secrets in .env file with pii unencrypted"
    result = run_policy_as_code_check.invoke({"design_text": insecure_design, "policy_engine": "OPA"})
    assert result["fail_count"] >= 2
    assert result["overall"] == "FAIL"
    assert any(r["rule_id"] == "zelis.auth.external_mtls" for r in result["results"])


def test_stride_threat_modeling():
    components = json.dumps([
        {"name": "API Gateway", "type": "api"},
        {"name": "Postgres DB", "type": "database"},
    ])
    threats = run_stride_threat_model.invoke({"components_json": components})
    assert len(threats) >= 2
    categories = [t["category"] for t in threats]
    assert any(c in categories for c in ["Spoofing", "Tampering", "Information Disclosure"])


def test_policy_compliance_and_framework_lookup():
    design = "Connecting over plain text http:// with hardcoded password in config file and no logging"
    violations = check_policy_compliance.invoke({"design_text": design})
    assert len(violations) >= 2

    framework_lookup = retrieve_framework_control.invoke({"framework": "OWASP ASVS", "query": "authentication"})
    assert framework_lookup["total"] > 0


def test_risk_rating_and_escalation():
    findings = json.dumps([
        {"title": "Unauthenticated Admin API", "severity": "critical", "likelihood": "high"},
        {"title": "Missing Security Headers", "severity": "low", "likelihood": "low"},
    ])
    rated = rate_and_prioritize_findings.invoke({"findings_json": findings})
    assert rated[0]["risk_score"] > rated[1]["risk_score"]
    assert rated[0]["needs_human_review"] is True

    # Report generation should escalate on critical findings
    report = generate_architecture_report.invoke({
        "design_name": "Test Design",
        "findings_json": json.dumps(rated),
        "threats_json": "[]",
        "violations_json": "[]",
        "assumptions": "Assumption 1|Assumption 2",
    })
    assert report["recommendation"] == "escalate"
    assert report["human_review_required"] is True


def test_arch_review_tools_registry_complete():
    assert len(ARCH_REVIEW_TOOLS) == 10


# ═══════════════════════════════════════════════════════════════════════════════
# USE CASE 2 TESTS: Penetration Testing Agent & Guardrails
# ═══════════════════════════════════════════════════════════════════════════════

def test_scope_gateway_blocks_out_of_scope():
    allowed, _ = _check_scope("dev.zelis.internal")
    assert allowed is True

    blocked_target, reason = _check_scope("prod.zelis.com")
    assert blocked_target is False
    assert "OUT OF SCOPE" in reason or "explicitly excluded" in reason

    unauthorized_ip, reason2 = _check_scope("8.8.8.8")
    assert unauthorized_ip is False
    assert "NOT in approved scope" in reason2 or "Not in authorized target list" in reason2


def test_kill_switch_immediately_halts_tools():
    activate_kill_switch()
    is_killed, msg = _check_kill_switch()
    assert is_killed is True
    assert "KILL SWITCH ACTIVE" in msg

    # Tool call should be blocked
    result = run_port_scan.invoke({"target": "dev.zelis.internal", "port_range": "80,443"})
    assert result.get("blocked") is True

    # Clearing kill switch resumes operations
    deactivate_kill_switch()
    is_killed2, _ = _check_kill_switch()
    assert is_killed2 is False


def test_test_window_enforcement():
    # Set past window
    set_active_scope({
        "engagement_name": "Expired Test",
        "in_scope_targets": ["dev.zelis.internal"],
        "test_window_start": "2020-01-01T00:00:00Z",
        "test_window_end": "2020-01-02T00:00:00Z",
    })
    in_window, msg = _check_test_window()
    assert in_window is False
    assert "Test window has ended" in msg


def test_rate_limiting_enforcement():
    set_active_scope({
        "engagement_name": "Throttled Test",
        "in_scope_targets": ["dev.zelis.internal"],
        "rate_limit_rps": 2,
    })
    # First 2 allowed
    assert _check_rate_limit()[0] is True
    assert _check_rate_limit()[0] is True
    # 3rd in same second should be throttled
    allowed, msg = _check_rate_limit()
    assert allowed is False
    assert "Rate limit exceeded" in msg


def test_human_approval_gate_for_intrusive_actions():
    initial_approvals = len(get_approval_requests())
    approval_resp = request_human_approval.invoke({
        "action_type": "sql_injection_probe",
        "description": "Probe database endpoint for parameter injection",
        "target": "dev.zelis.internal",
        "risk_level": "high",
        "justification": "Verify whether payment query parameter is injectable",
    })
    assert approval_resp["status"] == "pending"
    assert "PAUSED" in approval_resp["message"]
    assert len(get_approval_requests()) == initial_approvals + 1


def test_safe_poc_validation_blocks_destructive_commands():
    # Destructive command must be blocked
    destructive = validate_proof_of_concept.invoke({
        "vulnerability_id": "VULN-001",
        "target": "dev.zelis.internal",
        "poc_command": "rm -rf /var/www && drop database users",
    })
    assert destructive.get("blocked") is True
    assert destructive.get("dangerous_keyword_detected") is True

    # A PoC for a finding that was never discovered cannot be validated — this is
    # the "no fabrication" guardrail: scans must run first.
    unknown = validate_proof_of_concept.invoke({
        "vulnerability_id": "VULN-DOES-NOT-EXIST",
        "target": "dev.zelis.internal",
        "poc_command": "curl -s -I http://dev.zelis.internal/health",
    })
    assert unknown.get("blocked") is True
    assert unknown.get("validated") is False

    # Run a scan so the finding actually exists, then validate it safely.
    scan = run_vulnerability_scanner.invoke({"target": "dev.zelis.internal", "scan_type": "passive"})
    finding_id = scan["vulnerabilities"][0]["id"]
    safe = validate_proof_of_concept.invoke({
        "vulnerability_id": finding_id,
        "target": "dev.zelis.internal",
        "poc_command": "curl -s -I http://dev.zelis.internal/actuator/env",
    })
    assert safe.get("validated") is True
    assert safe.get("destructive") is False


def test_retest_vulnerability_workflow():
    # Discover and validate a finding first — retest must not fabricate results.
    scan = run_vulnerability_scanner.invoke({"target": "dev.zelis.internal", "scan_type": "passive"})
    finding_id = scan["vulnerabilities"][0]["id"]
    validate_proof_of_concept.invoke({
        "vulnerability_id": finding_id,
        "target": "dev.zelis.internal",
        "poc_command": "curl -s -I http://dev.zelis.internal/health",
    })

    retest = retest_vulnerability.invoke({
        "vulnerability_id": finding_id,
        "target": "dev.zelis.internal",
        "remediation_notes": "Added OAuth 2.0 PKCE authentication gateway and removed plaintext endpoints",
    })
    assert retest["status"] == "remediated"

    # A vague remediation note must not confirm a fix.
    vague = retest_vulnerability.invoke({
        "vulnerability_id": finding_id,
        "target": "dev.zelis.internal",
        "remediation_notes": "looked into it",
    })
    assert vague["status"] == "inconclusive"


def test_purge_engagement_data():
    # Purge without exact confirmation string is rejected
    rejected = purge_engagement_data.invoke({"engagement_name": "Test Engagement", "confirm": "yes"})
    assert rejected["purged"] is False

    # Purge with exact string succeeds
    purged = purge_engagement_data.invoke({"engagement_name": "Test Engagement", "confirm": "CONFIRM_PURGE"})
    assert purged["purged"] is True


def test_immutable_audit_logging():
    log = get_audit_log()
    assert len(log) > 0
    latest = log[-1]
    assert "timestamp" in latest
    assert "action" in latest
    assert "target" in latest


# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

client = TestClient(app)


def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "architecture_review" in data["agents"]
    assert "penetration_testing" in data["agents"]


def test_api_kill_switch_routes():
    res = client.post("/api/pentest/kill-switch/activate")
    assert res.status_code == 200
    assert res.json()["status"] == "activated"

    status_res = client.get("/api/pentest/kill-switch")
    assert status_res.status_code == 200
    assert status_res.json()["kill_switch_active"] is True

    res2 = client.post("/api/pentest/kill-switch/deactivate")
    assert res2.status_code == 200
    assert res2.json()["status"] == "deactivated"


def test_api_start_pentest_rejected_when_kill_switch_active():
    client.post("/api/pentest/kill-switch/activate")
    payload = {
        "target_name": "Blocked engagement",
        "in_scope_targets": ["dev.zelis.internal"],
        "out_of_scope": [],
        "authorized_by": "Ops Lead",
        "test_window_start": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "test_window_end": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
    res = client.post("/api/pentest/start", json=payload)
    assert res.status_code == 423
    assert "kill switch" in res.json()["detail"].lower()
    client.post("/api/pentest/kill-switch/deactivate")


def test_api_retest_and_purge():
    # Discover a real finding so retest has something concrete to act on.
    scan = run_vulnerability_scanner.invoke({"target": "dev.zelis.internal", "scan_type": "passive"})
    finding_id = scan["vulnerabilities"][0]["id"]

    retest_payload = {
        "vulnerability_id": finding_id,
        "target": "dev.zelis.internal",
        "remediation_notes": "Patched with input parameterization",
    }
    res = client.post("/api/pentest/retest", json=retest_payload)
    assert res.status_code == 200
    assert res.json()["status"] in ("remediated", "inconclusive", "still_vulnerable")

    purge_payload = {
        "engagement_name": "Test Engagement",
        "confirm": "CONFIRM_PURGE",
    }
    purge_res = client.post("/api/pentest/purge", json=purge_payload)
    assert purge_res.status_code == 200
    assert purge_res.json()["purged"] is True


def test_api_poc_endpoint_enforces_scope_and_destructive_block():
    # Destructive PoC is blocked by the tool's safety filter.
    destructive = client.post("/api/pentest/poc", json={
        "vulnerability_id": "VULN-POC-1",
        "target": "dev.zelis.internal",
        "poc_command": "rm -rf /var/www",
    })
    assert destructive.status_code == 200
    assert destructive.json().get("blocked") is True

    # Discover a real finding first, then validate it with a safe PoC.
    scan = run_vulnerability_scanner.invoke({"target": "dev.zelis.internal", "scan_type": "passive"})
    finding_id = scan["vulnerabilities"][0]["id"]
    safe = client.post("/api/pentest/poc", json={
        "vulnerability_id": finding_id,
        "target": "dev.zelis.internal",
        "poc_command": "curl -s -I http://dev.zelis.internal/health",
    })
    assert safe.status_code == 200
    assert safe.json().get("validated") is True


def test_api_dfd_and_iac_endpoints():
    dfd_payload = {
        "components_json": json.dumps([{"name": "AuthService", "type": "service", "trust_zone": "DMZ"}]),
        "design_name": "Auth System",
    }
    dfd_res = client.post("/api/arch-review/dfd", json=dfd_payload)
    assert dfd_res.status_code == 200
    assert "graph TD" in dfd_res.json()["mermaid_diagram"]

    iac_payload = {
        "iac_text": "resource \"aws_s3_bucket\" \"b\" { public_access_block = false }",
        "iac_type": "terraform",
    }
    iac_res = client.post("/api/arch-review/iac-scan", json=iac_payload)
    assert iac_res.status_code == 200
    assert iac_res.json()["total_issues"] >= 1
