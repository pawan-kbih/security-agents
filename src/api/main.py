"""
Zelis Security Agents - FastAPI Backend
Provides REST API and SSE streaming for both security agents.
"""
from __future__ import annotations
import asyncio
import json
import os
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# Import agents
from src.agents.arch_review_agent import run_arch_review
from src.agents.pentest_agent import run_pentest
from src.tools.pentest_tools import (
    get_audit_log, get_approval_requests, _APPROVAL_REQUESTS,
    activate_kill_switch, deactivate_kill_switch, purge_engagement_data,
    retest_vulnerability, get_findings_db, validate_proof_of_concept,
)
import src.tools.pentest_tools as pentest_module
from src.tools.arch_review_tools import (
    generate_data_flow_diagram, parse_iac_config,
    run_policy_as_code_check, ask_clarifying_questions
)

app = FastAPI(
    title="Zelis Security Agents API",
    description="AI-powered security architecture review and penetration testing agents",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores
_reviews: dict[str, dict] = {}
_pentests: dict[str, dict] = {}
_stream_queues: dict[str, asyncio.Queue] = {}


# ─── Request Models ────────────────────────────────────────────────────────────

class ArchReviewRequest(BaseModel):
    design_text: str
    design_name: str = "Unnamed Design"


class PentestRequest(BaseModel):
    target_name: str
    in_scope_targets: list[str]
    out_of_scope: list[str] = []
    allowed_techniques: list[str] = ["passive_recon", "port_scan", "web_enum", "safe_poc"]
    authorized_by: str
    test_window_start: str | None = None
    test_window_end: str | None = None
    rate_limit_rps: int = 10


class ApprovalRequest(BaseModel):
    approval_id: str
    approved: bool
    approver_name: str
    notes: str = ""


class RetestRequest(BaseModel):
    vulnerability_id: str
    target: str
    remediation_notes: str


class PocRequest(BaseModel):
    vulnerability_id: str
    target: str
    poc_command: str


class PurgeRequest(BaseModel):
    engagement_name: str
    confirm: str


class IacScanRequest(BaseModel):
    iac_text: str
    iac_type: str = "terraform"


class PolicyCheckRequest(BaseModel):
    design_text: str
    policy_engine: str = "OPA"


class DfdRequest(BaseModel):
    components_json: str
    design_name: str = "Architecture DFD"


class ClarifyRequest(BaseModel):
    questions_json: str
    context: str = ""


# ─── Helper: SSE Streaming ────────────────────────────────────────────────────

async def stream_events(session_id: str) -> AsyncGenerator[str, None]:
    queue = _stream_queues.get(session_id)
    if not queue:
        queue = asyncio.Queue()
        _stream_queues[session_id] = queue

    yield f"data: {json.dumps({'type': 'connected', 'session_id': session_id})}\n\n"

    while True:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=60.0)
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") == "complete":
                break
        except asyncio.TimeoutError:
            yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"


async def push_event(session_id: str, event: dict) -> None:
    if session_id in _stream_queues:
        await _stream_queues[session_id].put(event)


# ─── Architecture Review Endpoints ───────────────────────────────────────────

@app.post("/api/arch-review/start")
async def start_arch_review(request: ArchReviewRequest, background_tasks: BackgroundTasks):
    """Start a new architecture security review."""
    session_id = str(uuid.uuid4())
    _reviews[session_id] = {
        "id": session_id,
        "status": "running",
        "design_name": request.design_name,
        "started_at": datetime.utcnow().isoformat(),
        "report": None,
        "messages": [],
    }
    _stream_queues[session_id] = asyncio.Queue()

    async def run_and_stream():
        async def callback(event: dict):
            _reviews[session_id]["messages"].append(event)
            await push_event(session_id, event)

        try:
            report = await run_arch_review(request.design_text, callback)
            _reviews[session_id]["status"] = "complete"
            _reviews[session_id]["report"] = report
            await push_event(session_id, {"type": "complete", "report": report})
        except Exception as e:
            _reviews[session_id]["status"] = "error"
            _reviews[session_id]["error"] = str(e)
            await push_event(session_id, {"type": "error", "message": str(e)})

    background_tasks.add_task(run_and_stream)
    return {"session_id": session_id, "status": "started"}


@app.get("/api/arch-review/{session_id}/stream")
async def stream_arch_review(session_id: str):
    """Stream live updates from an architecture review session."""
    if session_id not in _reviews:
        raise HTTPException(status_code=404, detail="Session not found")
    return StreamingResponse(
        stream_events(session_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/arch-review/{session_id}/status")
async def get_arch_review_status(session_id: str):
    """Get the current status and report for an architecture review."""
    if session_id not in _reviews:
        raise HTTPException(status_code=404, detail="Session not found")
    return _reviews[session_id]


@app.get("/api/arch-review/sessions")
async def list_arch_reviews():
    """List all architecture review sessions."""
    return list(_reviews.values())


# ─── Penetration Test Endpoints ───────────────────────────────────────────────

@app.post("/api/pentest/start")
async def start_pentest(request: PentestRequest, background_tasks: BackgroundTasks):
    """Start a new penetration test engagement."""
    if pentest_module._KILL_SWITCH:
        raise HTTPException(
            status_code=423,
            detail="Pentest start rejected: kill switch active. All testing is halted.",
        )

    session_id = str(uuid.uuid4())
    scope = {
        "target_name": request.target_name,
        "in_scope_targets": request.in_scope_targets,
        "out_of_scope": request.out_of_scope,
        "allowed_techniques": request.allowed_techniques,
        "authorized_by": request.authorized_by,
        "test_window_start": request.test_window_start,
        "test_window_end": request.test_window_end,
        "rate_limit_rps": request.rate_limit_rps,
        "authorization_token": str(uuid.uuid4()),
    }

    _pentests[session_id] = {
        "id": session_id,
        "status": "running",
        "target_name": request.target_name,
        "started_at": datetime.utcnow().isoformat(),
        "scope": scope,
        "report": None,
        "messages": [],
    }
    _stream_queues[session_id] = asyncio.Queue()

    async def run_and_stream():
        async def callback(event: dict):
            _pentests[session_id]["messages"].append(event)
            await push_event(session_id, event)

        try:
            report = await run_pentest(scope, callback)
            _pentests[session_id]["status"] = "complete"
            _pentests[session_id]["report"] = report
            await push_event(session_id, {"type": "complete", "report": report})
        except Exception as e:
            _pentests[session_id]["status"] = "error"
            _pentests[session_id]["error"] = str(e)
            await push_event(session_id, {"type": "error", "message": str(e)})

    background_tasks.add_task(run_and_stream)
    return {"session_id": session_id, "status": "started", "scope": scope}


@app.get("/api/pentest/{session_id}/stream")
async def stream_pentest(session_id: str):
    """Stream live updates from a pentest session."""
    if session_id not in _pentests:
        raise HTTPException(status_code=404, detail="Session not found")
    return StreamingResponse(
        stream_events(session_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/pentest/{session_id}/status")
async def get_pentest_status(session_id: str):
    if session_id not in _pentests:
        raise HTTPException(status_code=404, detail="Session not found")
    return _pentests[session_id]


@app.get("/api/pentest/sessions")
async def list_pentests():
    return list(_pentests.values())


# ─── Approval Endpoints ───────────────────────────────────────────────────────

@app.get("/api/approvals/pending")
async def get_pending_approvals():
    """Get all pending human approval requests."""
    all_approvals = get_approval_requests()
    return [a for a in all_approvals if a.get("status") == "pending"]


@app.get("/api/approvals/all")
async def get_all_approvals():
    return get_approval_requests()


@app.post("/api/approvals/{approval_id}/decide")
async def decide_approval(approval_id: str, request: ApprovalRequest):
    """Approve or reject a pending action."""
    for approval in _APPROVAL_REQUESTS:
        if approval["id"] == approval_id:
            approval["status"] = "approved" if request.approved else "rejected"
            approval["approved_by"] = request.approver_name
            approval["approved_at"] = datetime.utcnow().isoformat()
            approval["notes"] = request.notes
            return {"message": "Decision recorded", "approval": approval}
    raise HTTPException(status_code=404, detail="Approval request not found")


# ─── Audit Log Endpoint ───────────────────────────────────────────────────────

@app.get("/api/audit-log")
async def get_audit_log_endpoint():
    """Get the immutable audit log of all agent actions."""
    return get_audit_log()


# ─── Pentest Guardrails: Kill Switch, Retest, Purge ───────────────────────────

@app.get("/api/pentest/kill-switch")
async def get_kill_switch():
    """Check the current status of the emergency kill switch."""
    return {"kill_switch_active": pentest_module._KILL_SWITCH}


@app.post("/api/pentest/kill-switch/activate")
async def activate_kill_switch_endpoint():
    """Immediately halt all ongoing and future pentest operations."""
    activate_kill_switch()
    return {"status": "activated", "message": "⛔ Emergency kill switch activated. All tool calls halted."}


@app.post("/api/pentest/kill-switch/deactivate")
async def deactivate_kill_switch_endpoint():
    """Deactivate the emergency kill switch to allow operations."""
    deactivate_kill_switch()
    return {"status": "deactivated", "message": "✅ Kill switch cleared. Operations resumed."}


@app.post("/api/pentest/retest")
async def retest_endpoint(req: RetestRequest):
    """Retest a vulnerability after remediation to confirm the fix."""
    result = retest_vulnerability.invoke({
        "vulnerability_id": req.vulnerability_id,
        "target": req.target,
        "remediation_notes": req.remediation_notes,
    })
    return result


@app.post("/api/pentest/poc")
async def poc_endpoint(req: PocRequest):
    """Run a safe, non-destructive proof-of-concept validation.
    The scope gateway, kill switch, rate limit, and destructive-command
    block are all enforced inside the tool before anything runs."""
    result = validate_proof_of_concept.invoke({
        "vulnerability_id": req.vulnerability_id,
        "target": req.target,
        "poc_command": req.poc_command,
    })
    return result


@app.post("/api/pentest/purge")
async def purge_endpoint(req: PurgeRequest):
    """Purge credentials and sensitive engagement data per Zelis policy."""
    result = purge_engagement_data.invoke({
        "engagement_name": req.engagement_name,
        "confirm": req.confirm,
    })
    return result


@app.get("/api/pentest/findings")
async def get_pentest_findings():
    """Get all findings from the findings database."""
    return get_findings_db()


# ─── Architecture Review Extended Capabilities ───────────────────────────────

@app.post("/api/arch-review/dfd")
async def generate_dfd_endpoint(req: DfdRequest):
    """Generate a Mermaid.js Data Flow Diagram from component list."""
    result = generate_data_flow_diagram.invoke({
        "components_json": req.components_json,
        "design_name": req.design_name,
    })
    return result


@app.post("/api/arch-review/iac-scan")
async def iac_scan_endpoint(req: IacScanRequest):
    """Scan Infrastructure-as-Code for security misconfigurations."""
    result = parse_iac_config.invoke({
        "iac_text": req.iac_text,
        "iac_type": req.iac_type,
    })
    return result


@app.post("/api/arch-review/policy-check")
async def policy_check_endpoint(req: PolicyCheckRequest):
    """Run automated policy-as-code (OPA) rules against a design."""
    result = run_policy_as_code_check.invoke({
        "design_text": req.design_text,
        "policy_engine": req.policy_engine,
    })
    return result


@app.post("/api/arch-review/clarify")
async def clarify_questions_endpoint(req: ClarifyRequest):
    """Ask clarifying questions regarding missing architecture details."""
    result = ask_clarifying_questions.invoke({
        "questions_json": req.questions_json,
        "context": req.context,
    })
    return result


# ─── Health & Info ────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "agents": ["architecture_review", "penetration_testing"],
        "llm_model": os.getenv("OPENAI_MODEL", "gpt-4o"),
        "timestamp": datetime.utcnow().isoformat(),
    }


# ─── Serve Frontend ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the built frontend if present, otherwise redirect to API docs."""
    import os
    index_path = os.path.join("frontend", "dist", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            return HTMLResponse(content=f.read())
    return RedirectResponse(url="/docs")
