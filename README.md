# Zelis Security Agents

An AI-assisted security operations console built for a Zelis-style architecture review and
penetration testing workflow. An agent does the first-pass work, and a human approves anything
high-risk before it proceeds.

The project pairs a **Python FastAPI backend** with a **React + Vite frontend** and is meant to
feel like a realistic internal security control centre rather than a generic chatbot demo.

---

## Assessment intent

This build maps directly onto the two use cases in the assessment brief:

- **Use case 1 — Security Architecture Review Agent:** reviews a design as a first pass and routes
  high-risk items to a human architect.
- **Use case 2 — Penetration Testing Agent:** assists with reconnaissance, testing, and reporting,
  and pauses for human approval before any intrusive action.

Both agents share a common foundation: a fixed workflow graph, least-privilege tools, structured
JSON findings so code (not the model) handles scoring and routing, an approval queue, and an
append-only, in-memory audit log.

---

## What this app demonstrates

### 1. Architecture review workflow
Accepts a design description plus optional IaC input, then runs structured checks against:

- STRIDE threat modeling — mapped to **each component and each data flow**
- OWASP ASVS control lookups
- policy-as-code evaluation (OPA/Conftest style)
- infrastructure misconfiguration review (Terraform, Kubernetes, Docker, CloudFormation)
- severity + likelihood rating with a written rationale for every finding
- prioritisation and a final recommendation

Produces a recommendation of **pass**, **conditional_pass**, or **escalate**, and creates a pending
approval request whenever escalation is required.

### 2. Pentest / validation workflow
Models a secure testing environment with real, code-enforced controls:

- signed scope with in-scope / out-of-scope targets
- rules-of-engagement technique allow-list
- test-window enforcement
- rate limiting
- kill switch
- a genuine approval gate before intrusive actions
- safe, non-destructive proof-of-concept validation
- retest with evidence, plus credential sealing and end-of-engagement purge

### 3. Approval queue
The human gate in the process. High-risk actions stay pending until a reviewer approves or rejects
them. Approvals are enforced, not advisory — see the guardrail section below.

### 4. Audit trail
Actions, blocks, approvals, rejections, and guardrail events are recorded in an in-memory,
append-only log with timestamps, targets, and parameters. The log is available during the running
process but is not durable across restarts or tamper-proof storage.

### 5. Tool suite and proof-of-concept demos
A set of interactive panels for:

- safe PoC validation
- retest / MTTR tracking
- IaC scanning output
- OPA policy results
- attack-path summaries mapped to MITRE ATT&CK
- the purge workflow for sensitive artifacts

---

## Guardrail model

The design principle throughout: **the agent advises, but a human approves anything high-risk.**
The key controls are:

- human approval before high-risk actions
- hard scope enforcement for testing activities
- test-window restrictions
- rate limits
- kill switch interrupt capability
- append-only audit logging for the lifetime of the running process

### What is enforced in code vs. simulated

This is an honest statement of the boundary of the prototype.

**Enforced in code (real behaviour):**

- **Scope gateway** — `_check_scope` fails *closed*: an empty or unconfigured scope blocks every
  tool call. Out-of-scope and lookalike domains (for example `api.example.com.evil.net`) are
  refused by exact host matching.
- **Rules-of-engagement technique allow-list** — `_check_technique` refuses any technique not in
  the signed scope's `allowed_techniques`. Intrusive techniques (`exploit`, `bruteforce`, `dos`,
  `exfiltration`) are never auto-permitted.
- **Approval gate** — creating an approval request is not enough. A LangGraph `approval_gate` node
  halts the graph at `END` whenever an approval is pending, and `_is_approved` blocks intrusive
  tools until a human has approved the matching request.
- **Kill switch, rate limit, test window** — checked before every tool call.
- **Destructive PoC block** — mutating HTTP verbs, shell metacharacters, and destructive tooling
  are refused before execution.
- **Findings persistence & retest integrity** — scanner output is persisted so PoC validation and
  retest operate on real findings. Retest only reports `remediated` when the finding was previously
  validated *and* the remediation note describes a concrete control change; otherwise it reports
  `inconclusive` or `still_vulnerable`.
- **In-memory append-only audit log** — actions, blocks, approvals, and purges are recorded while
  the process is running. The log is not persisted across restarts or protected against in-process
  modification.
- **Credential sealing & purge** — captured credentials are stored sealed (never plaintext) and
  `purge_engagement_data` wipes credentials, findings, and the active scope, reporting real counts.

**Simulated (documented, by design):**

- **The scanners themselves** — Nmap, httpx, nuclei, and OWASP ZAP output is generated
  deterministically rather than by invoking the real tools. A production deployment swaps the
  simulated functions for real invocations; the surrounding scope, technique, approval, and audit
  controls are already real and would not change.
- **IaC / OPA checks** — policy results come from an in-memory policy knowledge base rather than a
  live OPA / Conftest / Checkov run.
- **LLM reasoning** — with no `OPENAI_API_KEY`, both agents fall back to a deterministic heuristic
  report so the workflow always produces output. With a key set, the agents reason over the real
  tool set via `ChatOpenAI` + `bind_tools`.

The governance layer is real code; the external tooling is a stand-in that maps 1:1 to the named
production tools.

### Demonstrating the approval gate

The pentest fallback creates a real approval request when the scope names privileged or
admin-facing targets (any of `admin`, `gateway`, `internal`, `privilege`, `elevated`). Because the
demo target `dev.zelis.internal` matches, a run against it will:

- create a pending approval, and
- return `paused_for_approval: true` with a recommendation of `escalate`.

A run against a plain target such as `api.example.com` completes with `conditional_pass` and no
pause. This is the clearest way to see the gate working end to end.

---

## Product structure

```bash
security-agents/
├── main.py                       # legacy entrypoint (start-dev.sh uses uvicorn directly)
├── start-dev.sh                  # runs backend + frontend together, Ctrl+C stops both
├── pyproject.toml                # Python dependencies and project config
├── .env.example                  # environment template (copy to .env)
├── README.md
├── src/
│   ├── agents/
│   │   ├── arch_review_agent.py  # LangGraph workflow + heuristic fallback
│   │   └── pentest_agent.py      # LangGraph workflow + approval_gate node + fallback
│   ├── api/
│   │   └── main.py               # FastAPI app and all routes
│   ├── models/
│   │   └── __init__.py           # Pydantic models for findings, threats, scope, reports
│   └── tools/
│       ├── arch_review_tools.py  # least-privilege, read-only review tools
│       └── pentest_tools.py      # scope gateway, scanners, approvals, PoC, retest, purge
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # dashboard: nav, tabs, stream panels, tool suite
│   │   └── index.css             # design system (light theme, indigo/violet/cyan accents)
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── tests/
    └── test_zelis_agents.py      # 28 tests across agents, guardrails, and API routes
```

---

## Tech stack

- **Python 3.11+**
- **FastAPI** — HTTP API and streaming responses
- **LangChain / LangGraph** — agent workflow graphs, tool binding, approval gate
- **Pydantic** — structured findings, scope, and report schemas
- **React 19** + **Vite** — dashboard UI
- **Pytest** — backend test suite

---

## Running the project locally

### 1. Install Python dependencies

```bash
uv sync --group dev
```

### 2. Install frontend dependencies

```bash
npm --prefix frontend install
```

### 3. Configure the environment (optional)

```bash
cp .env.example .env
```

Set `OPENAI_API_KEY` for live agent reasoning. Without it, both agents use the deterministic
heuristic fallback so everything still works.

### 4. Start both services

```bash
bash ./start-dev.sh
```

This starts the backend and frontend together and stops both when you press `Ctrl+C`.

- Frontend: http://127.0.0.1:5173
- Backend:  http://127.0.0.1:8000

The Vite app proxies `/api` calls to the FastAPI backend.

---

## Useful verification endpoints

```bash
# Backend health and registered agents
curl http://localhost:8000/api/health

# Pending approvals for the human gate
curl http://localhost:8000/api/approvals/pending

# Current kill switch state
curl http://localhost:8000/api/pentest/kill-switch

# Immutable audit log
curl http://localhost:8000/api/audit-log
```

---

## Assessment flow example

1. Open the dashboard.
2. Go to **Design Review** and submit a system description or architecture payload.
3. Review the findings, rationale, recommendation, and escalation output.
4. If a review escalates, check the **Approval Queue**.
5. Move to **Security Testing**, define an in-scope target and authorization context.
6. Watch the stream, guardrail checks, and kill-switch behaviour. With an internal/admin target the
   run pauses for approval.
7. Inspect **Audit Trail** entries for compliance evidence.
8. Use the **Tool Suite** for safe PoC demos, retests, IaC/OPA scans, and the purge workflow.

---

## Validation and quality checks

Run the Python tests:

```bash
uv run pytest tests/test_zelis_agents.py -q
```

Build the frontend bundle:

```bash
npm --prefix frontend run build
```

Lint the frontend:

```bash
npm --prefix frontend run lint
```

---

## UI design notes

The dashboard is a light-theme command centre with a colorful but readable palette:

- left-side navigation with a live posture panel (risk, pending approvals, findings)
- a header with breadcrumb, environment pill, and per-tab title/description
- right-side stream panels for live logs and findings
- tinted cards per section so each area has its own visual identity
- indigo, violet, and cyan accents with soft blue, teal, amber, and green card tints

Severity and status badges retain their red / amber / green meanings, while the brighter structural
accents make navigation, controls, and card sections easier to distinguish.

---

## Summary

This repository demonstrates a security-review operator experience where AI can help, but the
process still respects production governance: review, guardrails, approval, evidence, and
auditability. The agent workflows, scope gateway, approval gate, and audit trail are all real code;
the external scanners are a documented stand-in that maps to their production equivalents.
