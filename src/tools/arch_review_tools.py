"""
Zelis Security Agents - Architecture Review Tools (MCP-style, least-privilege)
Each tool is a pure function with read-only access.
"""
from __future__ import annotations
import json
import re
from typing import Any
from langchain_core.tools import tool
from src.models import (
    Component, Threat, PolicyViolation, ArchitectureReviewFinding,
    Severity, ReviewRecommendation
)


# ─── Simulated policy knowledge base ─────────────────────────────────────────

INTERNAL_POLICIES = {
    "AUTH-001": "All external-facing services MUST use MFA or OAuth 2.0 with PKCE.",
    "AUTH-002": "Service-to-service auth MUST use mTLS or short-lived JWT tokens.",
    "ENC-001": "All data classified as PII or PHI MUST be encrypted at rest (AES-256).",
    "ENC-002": "All inter-service communication MUST use TLS 1.2 or higher.",
    "SEC-001": "Secrets MUST be stored in an approved secrets manager (Vault/AWS SM).",
    "SEC-002": "No hardcoded credentials in source code or IaC.",
    "NET-001": "All services MUST operate on least-privilege network segmentation.",
    "LOG-001": "All authentication events and sensitive operations MUST be logged.",
    "DATA-001": "PII data MUST NOT be logged in plain text.",
    "DEPS-001": "Third-party dependencies MUST be scanned for CVEs before deployment.",
}

OWASP_ASVS_CONTROLS = {
    "V2.1.1": "Authentication: Passwords must be at least 12 characters or auto-generated.",
    "V2.8.1": "Authentication: Implement multi-factor authentication (MFA) for administrative access.",
    "V3.4.1": "Session Management: Cookie-based session tokens must use HttpOnly and Secure flags.",
    "V4.1.1": "Access Control: Principle of least privilege enforced across all endpoints.",
    "V6.2.1": "Cryptography: Encrypt all sensitive data at rest using AES-256.",
    "V7.1.1": "Error Handling: Application must not log credentials or payment details.",
    "V9.1.1": "Communications: TLS 1.3 must be used for all client connectivity.",
    "V13.1.3": "API Security: API URLs must not expose sensitive info (keys, tokens, passwords).",
    "V14.2.1": "Configuration: Third-party libraries must be verified for known vulnerabilities.",
}

CIS_BENCHMARKS = {
    "CIS-K8S-1.1": "Ensure API server anonymous auth is disabled.",
    "CIS-K8S-5.1": "Ensure image vulnerability scanning is enabled.",
    "CIS-AWS-1.1": "Avoid use of root account for everyday tasks.",
    "CIS-AWS-2.1": "Ensure CloudTrail is enabled in all regions.",
}

STRIDE_CATEGORIES = {
    "Spoofing": "Attacker impersonates a user or service",
    "Tampering": "Malicious modification of data or code",
    "Repudiation": "Denying an action was performed",
    "Information Disclosure": "Exposing data to unauthorized parties",
    "Denial of Service": "Disrupting service availability",
    "Elevation of Privilege": "Gaining unauthorized higher-level access",
}


@tool
def parse_design_document(design_text: str) -> dict[str, Any]:
    """
    Parse a design document and extract components, trust boundaries,
    data classification, and external dependencies. Returns a structured
    representation with trust zones and data classification labels.
    Read-only tool — only processes provided text.
    """
    components = []
    trust_boundaries = []
    data_flows = []
    external_deps = []
    clarifying_questions = []

    service_keywords = [
        "api", "service", "gateway", "database", "db", "cache",
        "queue", "frontend", "backend", "microservice", "lambda",
        "function", "container", "bucket", "storage", "dashboard",
        "proxy", "load balancer", "message broker", "event bus"
    ]

    data_classification_hints = {
        "pii": "PII", "phi": "PHI", "credit card": "PCI", "payment": "PCI",
        "password": "Sensitive", "secret": "Sensitive", "token": "Sensitive",
        "public": "Public", "internal": "Internal",
    }

    trust_zone_hints = {
        "public": "Public Zone", "internet": "Public Zone",
        "internal": "Trusted Zone", "private": "Trusted Zone",
        "dmz": "DMZ", "external": "External Zone",
    }

    text_lower = design_text.lower()
    lines = design_text.split()

    for word in lines:
        word_lower = word.lower().strip(".,:()\"-")
        for kw in service_keywords:
            if kw in word_lower and word_lower not in [c["name"] for c in components]:
                # Infer trust zone
                trust_zone = "Trusted Zone"  # default
                for hint, zone in trust_zone_hints.items():
                    if hint in text_lower:
                        trust_zone = zone
                        break

                # Infer data classification
                data_class = "Internal"
                for hint, classification in data_classification_hints.items():
                    if hint in text_lower:
                        data_class = classification
                        break

                components.append({
                    "name": word_lower,
                    "type": kw,
                    "trust_zone": trust_zone,
                    "data_classification": data_class,
                    "mentioned_in_design": True,
                })

    # Infer data flows from directional language
    import re
    flow_pattern = re.compile(r'(\w+)\s*[\-→>]+\s*(\w+)', re.IGNORECASE)
    for match in flow_pattern.findall(design_text):
        data_flows.append({"from": match[0], "to": match[1], "protocol": "unknown"})

    # Detect external dependencies
    ext_keywords = ["third-party", "external", "vendor", "aws", "gcp", "azure", "stripe", "twilio", "sendgrid"]
    for kw in ext_keywords:
        if kw in text_lower:
            external_deps.append(kw)

    # Generate clarifying questions for missing details
    if "secret" not in text_lower and ".env" not in text_lower and "vault" not in text_lower:
        clarifying_questions.append("Where are secrets and credentials stored? (e.g., Vault, AWS Secrets Manager, .env files)")
    if "auth" not in text_lower and "oauth" not in text_lower and "jwt" not in text_lower:
        clarifying_questions.append("How do services authenticate to each other? (e.g., mTLS, JWT, API keys)")
    if "encrypt" not in text_lower and "tls" not in text_lower and "https" not in text_lower:
        clarifying_questions.append("Is data encrypted in transit and at rest? What encryption standards are used?")
    if "log" not in text_lower and "audit" not in text_lower:
        clarifying_questions.append("What logging and audit trail mechanisms are in place?")
    if "backup" not in text_lower and "recovery" not in text_lower:
        clarifying_questions.append("What is the backup and disaster recovery strategy?")

    return {
        "raw_text": design_text[:500],
        "components": components[:12],
        "identified_components": components[:12],
        "component_count": len(components[:12]),
        "trust_boundaries": list(set([c["trust_zone"] for c in components])),
        "data_flows": data_flows[:10],
        "external_dependencies": list(set(external_deps)),
        "data_classification": list(set([c["data_classification"] for c in components])),
        "has_pii": "pii" in text_lower,
        "has_phi": "phi" in text_lower,
        "clarifying_questions": clarifying_questions,
        "requires_clarification": len(clarifying_questions) > 0,
    }


@tool
def run_stride_threat_model(components_json: str, data_flows_json: str = "[]") -> list[dict[str, Any]]:
    """
    Run a STRIDE threat model against the provided components JSON.
    Maps threats to each component AND each data flow (as required by the workflow).
    Returns a list of threat findings with severity and likelihood ratings.
    """
    try:
        components = json.loads(components_json)
    except Exception:
        components = [{"name": "unknown", "type": "service"}]

    try:
        data_flows = json.loads(data_flows_json) if data_flows_json else []
    except Exception:
        data_flows = []

    threats = []
    stride_map = {
        "api": [
            {"category": "Spoofing", "description": "API endpoint lacks strong auth", "severity": "high"},
            {"category": "Information Disclosure", "description": "API may leak sensitive data in error messages", "severity": "medium"},
            {"category": "Denial of Service", "description": "API lacks rate limiting", "severity": "medium"},
        ],
        "database": [
            {"category": "Tampering", "description": "Direct DB access without parameterized queries (SQL injection risk)", "severity": "critical"},
            {"category": "Information Disclosure", "description": "Database may be over-permissioned", "severity": "high"},
        ],
        "gateway": [
            {"category": "Elevation of Privilege", "description": "Gateway misconfiguration could bypass auth", "severity": "high"},
        ],
        "service": [
            {"category": "Repudiation", "description": "Service-to-service calls may lack audit logging", "severity": "medium"},
            {"category": "Spoofing", "description": "Service lacks mTLS for inter-service auth", "severity": "high"},
        ],
    }

    for component in components:
        comp_type = component.get("type", "service").lower()
        comp_name = component.get("name", "unknown")
        for key, threat_list in stride_map.items():
            if key in comp_type or key in comp_name:
                for t in threat_list:
                    threats.append({
                        "component": comp_name,
                        "element": comp_name,
                        "category": t["category"],
                        "description": t["description"],
                        "severity": t["severity"],
                        "stride_category_definition": STRIDE_CATEGORIES.get(t["category"], ""),
                        "likelihood": _derive_likelihood(t["severity"], component),
                        "mitigations": [f"Apply {t['category']} mitigations per OWASP ASVS"],
                        "framework_reference": "OWASP ASVS V1.1 / STRIDE",
                    })

    # Threat-model every data flow (STRIDE over the flow itself).
    flow_stride = [
        {"category": "Tampering", "description": "Data in transit can be modified if integrity is not enforced", "severity": "high"},
        {"category": "Information Disclosure", "description": "Flow may expose sensitive data if not encrypted in transit", "severity": "high"},
    ]
    for flow in data_flows:
        frm = flow.get("from", "unknown")
        to = flow.get("to", "unknown")
        data = flow.get("data", "unspecified data")
        for t in flow_stride:
            threats.append({
                "component": f"flow:{frm}->{to}",
                "element": f"{frm} → {to}",
                "category": t["category"],
                "description": f"{t['description']} ({data})",
                "severity": t["severity"],
                "stride_category_definition": STRIDE_CATEGORIES.get(t["category"], ""),
                "likelihood": _derive_likelihood(t["severity"], {"data_classification": flow.get("data_classification")}),
                "mitigations": [f"Apply {t['category']} mitigations to the {frm}→{to} flow (mTLS + encryption)"],
                "framework_reference": "OWASP ASVS V9.1 / STRIDE",
            })

    return threats[:30]  # Cap for readability


def _derive_likelihood(severity: str, component: dict[str, Any]) -> str:
    """Derive a likelihood rating from severity and exposure signals rather than
    hardcoding 'medium' for every threat."""
    classification = str(component.get("data_classification", "")).lower()
    zone = str(component.get("trust_zone", "")).lower()
    exposed = any(token in zone for token in ["public", "dmz", "external", "internet"])
    sensitive = any(token in classification for token in ["pii", "pci", "sensitive", "confidential", "restricted"])
    if exposed and severity in ("critical", "high"):
        return "high"
    if sensitive and severity in ("critical", "high"):
        return "high"
    if exposed or sensitive:
        return "medium"
    return "low"


@tool
def ask_clarifying_questions(questions_json: str, context: str) -> dict[str, Any]:
    """
    Ask clarifying questions to the engineer when key design details are missing.
    Examples: where secrets are stored, how services authenticate, encryption strategy.
    Returns simulated answers (in production, these come from Jira/Confluence or the engineer).
    This is a mandatory step when parse_design_document returns requires_clarification=True.
    """
    try:
        questions = json.loads(questions_json) if questions_json.strip().startswith("[") else [questions_json]
    except Exception:
        questions = [questions_json]

    # Simulated engineer responses (in production: async Jira comment / Slack thread)
    answer_map = {
        "secret": "Secrets are stored in HashiCorp Vault with per-service tokens.",
        "auth": "Services use mTLS for inter-service communication and OAuth 2.0 + PKCE for external users.",
        "encrypt": "AES-256 at rest via AWS KMS; TLS 1.3 in transit.",
        "log": "Structured JSON logs shipped to Splunk. Auth events use a dedicated audit log stream.",
        "backup": "Daily automated backups to S3 with 30-day retention. RTO: 4h, RPO: 1h.",
        "network": "Kubernetes NetworkPolicies enforce least-privilege segmentation per namespace.",
        "third-party": "All third-party libraries are scanned with Trivy in the CI pipeline.",
    }

    answers = []
    unanswered = []
    for q in questions:
        q_lower = q.lower()
        answered = False
        for keyword, answer in answer_map.items():
            if keyword in q_lower:
                answers.append({"question": q, "answer": answer, "answered": True})
                answered = True
                break
        if not answered:
            answers.append({
                "question": q,
                "answer": "No answer available — escalate to engineer.",
                "answered": False,
            })
            unanswered.append(q)

    return {
        "questions_asked": len(questions),
        "answers": answers,
        "unanswered": unanswered,
        "all_answered": len(unanswered) == 0,
        "context": context,
        "note": "In production, answers are sourced from Jira ticket comments or Confluence page updates.",
    }


@tool
def parse_iac_config(iac_text: str, iac_type: str = "terraform") -> dict[str, Any]:
    """
    Parse Infrastructure-as-Code (Terraform HCL, Kubernetes YAML, Dockerfile)
    to extract security-relevant configuration settings.
    Checks for common misconfigurations like public S3 buckets, privileged containers, etc.
    Read-only — processes provided IaC text only.
    """
    issues = []
    text_lower = iac_text.lower()

    if iac_type.lower() in ("terraform", "tf"):
        iac_checks = [
            ("public_access_block = false", "S3 bucket public access is not blocked", "high", "CIS-AWS-2.1"),
            ("publicly_accessible = true", "RDS instance is publicly accessible", "critical", "CIS-AWS-1.1"),
            ("encrypted = false", "Storage resource is not encrypted", "high", "ENC-001"),
            ("enable_deletion_protection = false", "Deletion protection disabled", "medium", "NET-001"),
            ('version = "http://', "Insecure HTTP endpoint in configuration", "high", "ENC-002"),
            ("password =\"\"", "Empty password detected in IaC", "critical", "SEC-002"),
        ]
    elif iac_type.lower() in ("kubernetes", "k8s", "yaml"):
        iac_checks = [
            ("privileged: true", "Container running in privileged mode", "critical", "CIS-K8S-5.1"),
            ("allowprivilegeescalation: true", "Privilege escalation allowed", "high", "CIS-K8S-1.1"),
            ("hostnetwork: true", "Container shares host network namespace", "high", "CIS-K8S-1.1"),
            ("runasroot: true", "Container running as root", "high", "CIS-K8S-5.1"),
            ("imagepullpolicy: never", "Image pull policy may use unverified local images", "medium", "CIS-K8S-5.1"),
            ('image: "latest"', "Unpinned container image tag", "medium", "DEPS-001"),
        ]
    else:
        iac_checks = [
            ("user root", "Dockerfile running as root user", "high", "CIS-K8S-5.1"),
            ("add http", "Dockerfile fetching from insecure HTTP URL", "high", "ENC-002"),
        ]

    for pattern, description, severity, control in iac_checks:
        if pattern in text_lower:
            issues.append({
                "pattern": pattern,
                "description": description,
                "severity": severity,
                "control": control,
                "remediation": f"Fix misconfiguration: {description}. Reference: {control}",
            })

    return {
        "iac_type": iac_type,
        "total_issues": len(issues),
        "critical": sum(1 for i in issues if i["severity"] == "critical"),
        "high": sum(1 for i in issues if i["severity"] == "high"),
        "issues": issues,
        "tool": "Checkov / Trivy / KICS (simulated)",
        "note": "In production, runs actual Checkov/Trivy/KICS scanners on the IaC files.",
    }


@tool
def run_policy_as_code_check(design_text: str, policy_engine: str = "OPA") -> dict[str, Any]:
    """
    Run automated policy-as-code checks (OPA / Conftest style) against the design.
    Evaluates structured policies and returns pass/fail/warn results per policy rule.
    This is more rigorous than text-based policy matching.
    """
    text_lower = design_text.lower()

    opa_rules = [
        {
            "rule_id": "zelis.auth.external_mtls",
            "description": "External services must use TLS with certificate auth",
            "result": "FAIL" if "http://" in text_lower and "no auth" in text_lower else "WARN" if "http://" in text_lower else "PASS",
            "severity": "critical",
            "framework": "AUTH-001 / OWASP ASVS V9.1.1",
        },
        {
            "rule_id": "zelis.secrets.no_plaintext",
            "description": "Secrets must not be stored in plaintext config or env files",
            "result": "FAIL" if ".env" in text_lower or "hardcoded" in text_lower else "PASS",
            "severity": "critical",
            "framework": "SEC-001 / SEC-002",
        },
        {
            "rule_id": "zelis.encryption.at_rest",
            "description": "All PII/PHI data must be encrypted at rest",
            "result": "FAIL" if ("pii" in text_lower or "phi" in text_lower) and "encrypt" not in text_lower else "PASS",
            "severity": "high",
            "framework": "ENC-001 / OWASP ASVS V6.2.1",
        },
        {
            "rule_id": "zelis.logging.auth_events",
            "description": "All auth events must be logged to immutable audit trail",
            "result": "FAIL" if "no logging" in text_lower or "no audit" in text_lower else "WARN" if "log" not in text_lower else "PASS",
            "severity": "medium",
            "framework": "LOG-001",
        },
        {
            "rule_id": "zelis.network.segmentation",
            "description": "Services must run in least-privilege network segments",
            "result": "WARN" if "network" not in text_lower and "vpc" not in text_lower else "PASS",
            "severity": "medium",
            "framework": "NET-001 / CIS-AWS-2.1",
        },
        {
            "rule_id": "zelis.deps.scanning",
            "description": "All third-party dependencies must be scanned for CVEs",
            "result": "WARN" if "third-party" in text_lower and "scan" not in text_lower else "PASS",
            "severity": "medium",
            "framework": "DEPS-001 / OWASP ASVS V14.2.1",
        },
    ]

    fail_count = sum(1 for r in opa_rules if r["result"] == "FAIL")
    warn_count = sum(1 for r in opa_rules if r["result"] == "WARN")

    return {
        "policy_engine": policy_engine,
        "rules_evaluated": len(opa_rules),
        "fail_count": fail_count,
        "warn_count": warn_count,
        "pass_count": len(opa_rules) - fail_count - warn_count,
        "results": opa_rules,
        "overall": "FAIL" if fail_count > 0 else "WARN" if warn_count > 0 else "PASS",
        "tool": f"{policy_engine} / Conftest (simulated)",
    }


@tool
def generate_data_flow_diagram(components_json: str, design_name: str) -> dict[str, Any]:
    """
    Generate a Mermaid.js data flow diagram (DFD) from the identified components.
    Shows trust boundaries, data flows, and classification labels.
    Returns Mermaid markdown that can be rendered in the dashboard or Confluence.
    """
    try:
        components = json.loads(components_json)
    except Exception:
        components = []

    lines = ["graph TD"]
    lines.append(f'    title["{design_name} - Data Flow Diagram"]')
    lines.append("    style title fill:#1a1a2e,stroke:#4f8ef7,color:#e8eaf6")

    # Group components by trust zone
    zones: dict[str, list] = {}
    for comp in components:
        zone = comp.get("trust_zone", "Trusted Zone")
        zones.setdefault(zone, []).append(comp)

    zone_styles = {
        "Public Zone": "fill:#2d1b1b,stroke:#ef4444",
        "Trusted Zone": "fill:#1b2d1b,stroke:#10b981",
        "External Zone": "fill:#1b1b2d,stroke:#4f8ef7",
        "DMZ": "fill:#2d2d1b,stroke:#eab308",
    }

    comp_ids = {}
    node_idx = 0
    for zone, comps in zones.items():
        safe_zone = zone.replace(" ", "_").replace("/", "_")
        lines.append(f"    subgraph {safe_zone}[\"{zone}\"]")
        for comp in comps:
            node_id = f"N{node_idx}"
            comp_ids[comp["name"]] = node_id
            data_class = comp.get("data_classification", "Internal")
            lines.append(f'        {node_id}["{comp["name"]}\\n({comp["type"]})\\n[{data_class}]"]')
            node_idx += 1
        lines.append("    end")
        style = zone_styles.get(zone, "fill:#1a1a2e,stroke:#4f8ef7")
        lines.append(f"    style {safe_zone} {style}")

    # Add data flows between adjacent components
    comp_list = [c["name"] for c in components]
    for i in range(len(comp_list) - 1):
        src = comp_ids.get(comp_list[i])
        dst = comp_ids.get(comp_list[i + 1])
        if src and dst:
            lines.append(f"    {src} -->|data flow| {dst}")

    mermaid_code = "\n".join(lines)

    return {
        "design_name": design_name,
        "mermaid_diagram": mermaid_code,
        "component_count": len(components),
        "trust_zones": list(zones.keys()),
        "render_hint": "Paste the mermaid_diagram into https://mermaid.live or any Mermaid renderer",
    }


@tool
def check_policy_compliance(design_text: str) -> list[dict[str, Any]]:
    """
    Check design against internal security policies (AUTH, ENC, SEC, NET, LOG, DATA, DEPS).
    Returns policy violations found in the design description.
    Read-only — searches provided text only.
    """
    violations = []
    text_lower = design_text.lower()

    checks = [
        ("AUTH-001", ["http://", "no auth", "no authentication", "unauthenticated", "anonymous"],
         "External service may lack proper authentication", "critical"),
        ("ENC-001", ["no encryption", "plain text", "plaintext", "unencrypted", "http://"],
         "Data may not be encrypted at rest", "high"),
        ("ENC-002", ["http://", "no tls", "without tls", "unencrypted transport"],
         "Communication may not use TLS", "high"),
        ("SEC-001", ["env variable", "environment variable", ".env", "config file", "hardcoded"],
         "Secrets storage method unclear or insecure", "high"),
        ("LOG-001", ["no logging", "without logging", "no audit"],
         "Authentication events may not be logged", "medium"),
        ("DEPS-001", ["npm install", "pip install", "no scanning", "unverified"],
         "Dependencies may not be scanned for vulnerabilities", "medium"),
    ]

    for policy_id, triggers, description, severity in checks:
        for trigger in triggers:
            if trigger in text_lower:
                violations.append({
                    "policy_id": policy_id,
                    "policy_name": INTERNAL_POLICIES.get(policy_id, policy_id),
                    "description": description,
                    "severity": severity,
                    "remediation": f"Comply with policy {policy_id}: {INTERNAL_POLICIES.get(policy_id, '')}",
                    "triggered_by": trigger,
                })
                break

    # Also check OWASP ASVS
    if "cookie" in text_lower and "httponly" not in text_lower:
        violations.append({
            "policy_id": "OWASP-ASVS-V3.4.1",
            "policy_name": OWASP_ASVS_CONTROLS["V3.4.1"],
            "description": "Cookie-based sessions may lack HttpOnly/Secure flags",
            "severity": "high",
            "remediation": "Set HttpOnly and Secure flags on all session cookies",
            "triggered_by": "cookie",
        })

    return violations


@tool
def retrieve_framework_control(framework: str, query: str) -> dict[str, Any]:
    """
    Retrieve a specific control from OWASP ASVS, CIS Benchmarks, or STRIDE.
    Read-only lookup into the knowledge base.
    """
    framework_upper = framework.upper()
    results = {}

    if "OWASP" in framework_upper or "ASVS" in framework_upper:
        for ctrl_id, description in OWASP_ASVS_CONTROLS.items():
            if query.lower() in description.lower():
                results[ctrl_id] = description

    if "CIS" in framework_upper:
        for ctrl_id, description in CIS_BENCHMARKS.items():
            if query.lower() in description.lower():
                results[ctrl_id] = description

    if "STRIDE" in framework_upper:
        results = STRIDE_CATEGORIES

    if "INTERNAL" in framework_upper or "POLICY" in framework_upper:
        for policy_id, description in INTERNAL_POLICIES.items():
            if query.lower() in description.lower():
                results[policy_id] = description

    return {
        "framework": framework,
        "query": query,
        "controls_found": results,
        "total": len(results),
    }


@tool
def rate_and_prioritize_findings(findings_json: str) -> list[dict[str, Any]]:
    """
    Rate and prioritize a list of security findings by severity and likelihood.
    Returns sorted findings with risk scores and remediation priority.
    """
    try:
        findings = json.loads(findings_json)
    except Exception:
        return []

    severity_score = {
        "critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 1
    }
    likelihood_score = {"high": 3, "medium": 2, "low": 1}

    for finding in findings:
        sev = finding.get("severity", "medium")
        lik = finding.get("likelihood", "medium")
        finding["risk_score"] = severity_score.get(sev, 5) * likelihood_score.get(lik, 2)
        finding["needs_human_review"] = finding["risk_score"] >= 20
        finding["remediation_priority"] = (
            "Immediate" if finding["risk_score"] >= 20
            else "Short-term" if finding["risk_score"] >= 10
            else "Backlog"
        )
        # Every finding must carry a rationale explaining WHY it was rated this way.
        if not finding.get("rationale"):
            component = finding.get("component", "the component")
            control = finding.get("framework_control") or finding.get("framework_reference") or "internal policy"
            finding["rationale"] = (
                f"Rated {sev} severity x {lik} likelihood (risk score {finding['risk_score']}) because "
                f"{finding.get('description', 'the design deviates from the required control')}. "
                f"This maps to {control}, and the affected element is {component}."
            )
        # Validate/normalize every finding against the canonical schema so malformed
        # records are caught here rather than surfacing as bad data downstream.
        try:
            validated = ArchitectureReviewFinding(
                title=finding.get("title") or finding.get("category", "Finding"),
                severity=sev if sev in severity_score else "medium",
                category=finding.get("category", "General"),
                component=finding.get("component", "unknown"),
                description=finding.get("description", ""),
                rationale=finding["rationale"],
                remediation=finding.get("remediation", "Apply the referenced control."),
                framework_control=control,
                needs_human_review=finding["needs_human_review"],
            )
            finding.setdefault("id", validated.id)
            finding["framework_control"] = validated.framework_control
        except Exception:
            # Schema validation is best-effort; never lose a finding because of it.
            finding.setdefault("framework_control", control)

    return sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)


@tool
def generate_architecture_report(
    design_name: str,
    findings_json: str,
    threats_json: str,
    violations_json: str,
    assumptions: str
) -> dict[str, Any]:
    """
    Generate the final architecture review report with recommendation.
    Produces a pass/conditional-pass/escalate recommendation.
    """
    try:
        findings = json.loads(findings_json)
        threats = json.loads(threats_json)
        violations = json.loads(violations_json)
    except Exception:
        findings, threats, violations = [], [], []

    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    threat_critical = sum(1 for t in threats if t.get("severity") == "critical")
    violation_critical = sum(1 for v in violations if v.get("severity") == "critical")

    if critical_count > 0 or threat_critical > 0 or violation_critical > 0:
        recommendation = "escalate"
        summary = f"ESCALATE: {critical_count} critical findings, {threat_critical} critical threats. Human architect review required."
    elif high_count > 2 or len(violations) > 3:
        recommendation = "conditional_pass"
        summary = f"CONDITIONAL PASS: {high_count} high-severity findings and {len(violations)} policy violations must be addressed."
    else:
        recommendation = "pass"
        summary = f"PASS: Design meets minimum security requirements with {len(findings)} minor findings."

    return {
        "design_name": design_name,
        "recommendation": recommendation,
        "summary": summary,
        "total_findings": len(findings),
        "critical_findings": critical_count,
        "high_findings": high_count,
        "policy_violations": len(violations),
        "threat_count": len(threats),
        "human_review_required": recommendation == "escalate",
        "assumptions": assumptions.split("|") if assumptions else [],
        "top_findings": findings[:5],
    }


# ─── Tool registry ────────────────────────────────────────────────────────────

ARCH_REVIEW_TOOLS = [
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
]
