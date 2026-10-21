"""
Zelis Security Agents - Architecture Review Agent (LangGraph)
Implements a structured workflow graph for first-pass security architecture review.
"""
from __future__ import annotations
import json
import os
import re
from typing import Any, Annotated, TypedDict
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langgraph.graph.message import add_messages
from src.tools.arch_review_tools import ARCH_REVIEW_TOOLS
from src.tools.pentest_tools import request_human_approval


SYSTEM_PROMPT = """You are the Zelis Security Architecture Review Agent — a first-pass security reviewer.

Your role:
1. Parse design documents and identify components, trust boundaries, data classification, and external dependencies
2. Ask clarifying questions when key details are missing (e.g., where secrets are stored, how services authenticate)
3. Generate a Mermaid data flow diagram (DFD) showing trust zones and data classifications
4. Parse any Infrastructure-as-Code (Terraform, Kubernetes, Dockerfile) for security misconfigurations
5. Run automated policy-as-code checks (OPA / Conftest rules)
6. Run a structured STRIDE threat model
7. Check designs against internal policies and OWASP ASVS / CIS Benchmarks
8. Rate each finding by severity and likelihood
9. Produce a structured review report with pass/conditional_pass/escalate recommendation

GUARDRAILS:
- You have READ-ONLY access to designs and configurations
- All your findings MUST cite the specific policy or framework control behind them
- You ADVISE only — a human approves anything high-risk (ESCALATE recommendation)
- Never store or transmit sensitive documents outside the approved boundary

WORKFLOW:
Step 1: Parse the design → identify components, trust boundaries & data classification
Step 2: If ambiguities or missing details exist, call ask_clarifying_questions
Step 3: Call generate_data_flow_diagram to visualize trust zones
Step 4: If IaC is present, run parse_iac_config; also run run_policy_as_code_check
Step 5: Run STRIDE threat model on components
Step 6: Check policy compliance and retrieve framework controls
Step 7: Rate and prioritize all findings
Step 8: Generate final report with pass/conditional-pass/escalate recommendation

Always be thorough, cite your sources, and think like an adversary."""


class ArchReviewState(TypedDict):
    messages: Annotated[list, add_messages]
    design_input: str
    review_complete: bool
    report: dict[str, Any]
    human_review_required: bool


def should_continue(state: ArchReviewState) -> str:
    """Determine if the agent should use tools or end."""
    messages = state["messages"]
    last_message = messages[-1]

    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "tools"

    # Check if review is complete (report was generated)
    for msg in reversed(messages):
        if hasattr(msg, "content") and isinstance(msg.content, str):
            if "recommendation" in msg.content.lower() and (
                "pass" in msg.content.lower() or "escalate" in msg.content.lower()
            ):
                return END
    return END


def _ensure_pending_architecture_approval(report: dict[str, Any]) -> dict[str, Any] | None:
    """Create a pending approval when the architecture review requires human sign-off."""
    rec = str(report.get("recommendation") or "").lower()
    requires_review = bool(report.get("human_review_required")) or rec in {"escalate", "conditional_pass"}
    if not requires_review:
        return None

    approval = request_human_approval.invoke({
        "action_type": "architecture_review_escalation",
        "description": "Architecture review requires a human reviewer to approve the design findings before any high-risk action proceeds.",
        "target": "architecture review / design review",
        "risk_level": "high" if rec == "escalate" else "medium",
        "justification": "The architecture review contains findings that need human validation before proceeding with implementation or deployment.",
    })
    return approval


def _fallback_arch_review_payload(design_text: str) -> dict[str, Any]:
    """Generate a deterministic report when the LLM is unavailable or does not return findings."""
    lowered = (design_text or "").lower()
    findings: list[dict[str, Any]] = []

    if "http://" in lowered or "plaintext" in lowered or "unencrypted" in lowered:
        findings.append({
            "title": "Sensitive traffic is exposed without strong transport protection",
            "severity": "high",
            "likelihood": "medium",
            "description": "The design references plaintext or insecure transport paths for sensitive traffic.",
            "rationale": "High severity because unencrypted transport exposes sensitive data to interception; likelihood medium because the issue depends on exposure of the path.",
            "mitigation": "Require TLS/mTLS for every external and internal service boundary.",
            "control": "OWASP ASVS V1 / transport security",
        })

    if any(token in lowered for token in ["secret", "password", "token", "credential", "api key"]):
        findings.append({
            "title": "Secrets and credentials need stronger handling",
            "severity": "high",
            "likelihood": "medium",
            "description": "The design mentions secrets, credentials, or tokens and should be validated for storage and rotation controls.",
            "rationale": "High severity because leaked credentials grant direct access to systems; likelihood medium pending confirmation of storage and rotation controls.",
            "mitigation": "Store secrets in a managed secret store, rotate them regularly, and avoid hard-coded values.",
            "control": "CIS / secret management controls",
        })

    if any(token in lowered for token in ["public", "internet", "alb", "gateway"]) and any(token in lowered for token in ["database", "db", "postgres", "rds"]):
        findings.append({
            "title": "Public access paths overlap with sensitive data stores",
            "severity": "critical",
            "likelihood": "medium",
            "description": "The design exposes public-facing access near trusted data services and should have tighter segmentation.",
            "rationale": "Critical severity because a public path to a sensitive data store can enable mass data compromise; likelihood medium given the described segmentation gap.",
            "mitigation": "Restrict direct public access, add private networking, and enforce least privilege.",
            "control": "Zelis trusted-zone segmentation policy",
        })

    if not findings:
        findings.append({
            "title": "Architecture review requires validation of trust boundaries and access controls",
            "severity": "medium",
            "likelihood": "medium",
            "description": "No high-confidence issue was detected from the supplied design text, but the design still needs formal review.",
            "rationale": "Medium severity and likelihood because the reviewed text is insufficient to confirm or rule out control gaps.",
            "mitigation": "Confirm identity boundaries, encryption controls, and operational safeguards before moving forward.",
            "control": "Internal architecture review policy",
        })

    recommendation = "escalate" if any(f.get("severity") == "critical" for f in findings) else "conditional_pass"
    summary = (
        f"Review completed with {len(findings)} finding(s). "
        f"Recommendation: {recommendation}."
    )

    return {
        "recommendation": recommendation,
        "summary": summary,
        "findings": findings,
        "total_findings": len(findings),
        "human_review_required": recommendation == "escalate",
    }


async def agent_node(state: ArchReviewState) -> dict:
    """Main agent reasoning node (async so LLM calls never block the event loop).

    If no LLM credentials are configured, or the call fails, fall back to the
    deterministic heuristic review so the workflow always produces a report.
    """
    messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]
    try:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY not configured — using heuristic fallback")
        llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            temperature=0,
        ).bind_tools(ARCH_REVIEW_TOOLS)
        response = await llm.ainvoke(messages)
    except Exception:
        fallback = _fallback_arch_review_payload(state.get("design_input", ""))
        response = AIMessage(content=json.dumps(fallback))

    return {"messages": [response]}


def build_arch_review_graph() -> Any:
    """Build and compile the architecture review LangGraph workflow."""
    graph = StateGraph(ArchReviewState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(ARCH_REVIEW_TOOLS))

    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile()


async def run_arch_review(design_text: str, stream_callback=None) -> dict[str, Any]:
    """
    Run the full architecture review workflow.
    Returns the final report as a structured dict.
    """
    app = build_arch_review_graph()

    initial_state: ArchReviewState = {
        "messages": [HumanMessage(content=f"""
Please perform a comprehensive security architecture review of the following design:

{design_text}

Follow the complete workflow:
1. Parse the design and identify all components
2. Run STRIDE threat modeling
3. Check policy compliance  
4. Rate and prioritize findings
5. Generate a final report with recommendation (pass/conditional_pass/escalate)

Use your tools systematically and be thorough.
""")],
        "design_input": design_text,
        "review_complete": False,
        "report": {},
        "human_review_required": False,
    }

    all_messages = []
    final_state = None
    dfd_diagram = ""

    async for mode, event in app.astream(
        initial_state, stream_mode=["updates", "values"]
    ):
        if mode == "updates":
            # Per-node updates: surface tool calls/results to the live stream.
            for node_output in event.values():
                for msg in node_output.get("messages", []):
                    tool_calls = getattr(msg, "tool_calls", None) or []
                    for tc in tool_calls:
                        if stream_callback:
                            await stream_callback({
                                "type": "tool_call",
                                "tool_name": tc.get("name", "tool"),
                                "args": tc.get("args", {}),
                            })
                    if getattr(msg, "name", None) and isinstance(msg, object) and msg.__class__.__name__ == "ToolMessage":
                        result: Any = msg.content
                        if isinstance(result, str) and result.strip().startswith(("{", "[")):
                            try:
                                result = json.loads(result)
                            except Exception:
                                pass
                        if isinstance(result, dict) and result.get("mermaid_diagram"):
                            dfd_diagram = result["mermaid_diagram"]
                        if stream_callback:
                            await stream_callback({
                                "type": "tool_result",
                                "tool_name": msg.name,
                                "result": result if isinstance(result, (dict, list)) else str(result)[:400],
                            })
            continue

        # Full state snapshots (values mode).
        final_state = event
        if stream_callback and "messages" in event:
            for msg in event["messages"]:
                if msg not in all_messages:
                    all_messages.append(msg)
                    if hasattr(msg, "content") and msg.content and not getattr(msg, "tool_calls", None):
                        await stream_callback({"type": "message", "content": str(msg.content)[:500]})

    # Extract report from messages
    report = {
        "summary": "Review completed",
        "messages_count": len(all_messages),
        "findings": [],
        "recommendation": "conditional_pass",
    }
    if final_state:
        for msg in reversed(final_state.get("messages", [])):
            content = getattr(msg, "content", "")
            if isinstance(content, str) and len(content) > 0:
                payload = None
                cleaned = content.strip()
                if cleaned.startswith("{") or cleaned.startswith("["):
                    try:
                        payload = json.loads(cleaned)
                    except Exception:
                        payload = None
                if isinstance(payload, dict):
                    if "findings" in payload:
                        report["findings"] = payload.get("findings", [])
                    if "recommendation" in payload:
                        report["recommendation"] = payload.get("recommendation", "conditional_pass")
                    if "summary" in payload:
                        report["summary"] = payload.get("summary", report["summary"])
                    if payload.get("total_findings") is not None:
                        report["total_findings"] = payload.get("total_findings")
                    if payload.get("human_review_required") is not None:
                        report["human_review_required"] = bool(payload.get("human_review_required"))
                    if "final_analysis" in payload:
                        report["final_analysis"] = payload.get("final_analysis")
                    if report["findings"]:
                        break
                report["final_analysis"] = content[:2000]
                break

    if not report.get("findings"):
        fallback = _fallback_arch_review_payload(design_text)
        report.update(fallback)

    if dfd_diagram:
        report["mermaid_diagram"] = dfd_diagram

    approval = _ensure_pending_architecture_approval(report)
    if approval:
        report["approval_requests"] = [approval]
        report["human_review_required"] = True
        if report.get("recommendation") == "pass":
            report["recommendation"] = "conditional_pass"

    return report
