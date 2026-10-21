import { useCallback, useEffect, useRef, useState } from 'react'

// ─── Constants ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'arch',      label: 'Design Review',    icon: '🏗️',
    description: 'Threat-model architecture documents with STRIDE, OWASP ASVS, policy-as-code, and IaC checks before anything ships.' },
  { id: 'pentest',   label: 'Security Testing', icon: '🔍',
    description: 'Scope-gated penetration testing with rate limits, proof-of-concept validation, and human approval on every destructive action.' },
  { id: 'approvals', label: 'Approval',         icon: '✅',
    description: 'Review and decide on actions the agents have paused. Nothing elevated proceeds without a named approver.' },
  { id: 'tools',     label: 'Tools',            icon: '🧪',
    description: 'Exercise individual agent tools directly — scanners, policy engines, PoC generators, and retest workflows.' },
  { id: 'audit',     label: 'Audit Trail',      icon: '📋',
    description: 'Immutable, append-only record of every agent action, scope decision, and guardrail enforcement event.' },
]

const ARCH_FEATURES = [
  { label: 'STRIDE threat model',    icon: '🎯' },
  { label: 'OWASP ASVS checks',      icon: '🔒' },
  { label: 'Policy-as-code (OPA)',   icon: '📜' },
  { label: 'IaC misconfiguration',   icon: '☁️'  },
  { label: 'Risk prioritization',    icon: '📊' },
  { label: 'Human escalation',       icon: '👷' },
]

const SAMPLE_ARCH_DESIGN = `Zelis Payments Platform architecture\n\nPublic users access the web app through an AWS ALB and Kubernetes ingress. The frontend calls the Payments API over OAuth 2.0 and mTLS. The Payments service reads and writes customer and provider data in Amazon RDS, caches session data in ElastiCache, and calls downstream fintech partners through a secure gateway.\n\nSensitive payment metadata, customer identifiers, and tokenized credentials are handled inside the trusted zone and written to encrypted storage. Internal admin functions are restricted to SSO-authenticated operators through a private network and require explicit approval for elevated access.`

const SAMPLE_IAC = `resource "aws_security_group" "payments_api" {\n  name        = "payments-api-sg"\n  description = "Allow ingress from ALB and internal services"\n\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n\nresource "aws_db_instance" "payments" {\n  allocated_storage    = 100\n  engine               = "postgres"\n  publicly_accessible  = false\n  backup_retention_period = 7\n  storage_encrypted    = true\n}`

const SAMPLE_PENTEST_SCOPE = `api.staging.zelis.example.com\npayments-staging.zelis.example.com\nadmin-gateway.internal.zelis.example.com`

const SAMPLE_APPROVALS = [
  {
    id: 'APP-1041',
    action: 'Validate admin API auth flows against staging environment',
    target: 'admin-gateway.internal.zelis.example.com',
    status: 'pending',
    rationale: 'Requires explicit approval before testing authentication bypass or privilege escalation scenarios.',
    risk_level: 'high',
  },
  {
    id: 'APP-1042',
    action: 'Run safe PoC against token validation logic',
    target: 'api.staging.zelis.example.com',
    status: 'approved',
    rationale: 'Pre-authorized validation of non-destructive OAuth or JWT edge cases.',
    risk_level: 'medium',
    approved_by: 'M. Smith',
    approved_at: '2026-10-20T11:20:00Z',
  },
]

const SAMPLE_AUDIT = [
  { timestamp: '2026-10-20T11:00:00Z', action: 'scope_validation',    target: 'api.staging.zelis.example.com',            result: 'approved' },
  { timestamp: '2026-10-20T11:04:12Z', action: 'port_scan',           target: 'payments-staging.zelis.example.com',       result: 'ok'       },
  { timestamp: '2026-10-20T11:08:44Z', action: 'web_enum',            target: 'api.staging.zelis.example.com',            result: 'ok'       },
  { timestamp: '2026-10-20T11:13:01Z', action: 'auth_probe',          target: 'admin-gateway.internal.zelis.example.com', result: 'blocked'  },
  { timestamp: '2026-10-20T11:18:29Z', action: 'rate_limit_check',    target: 'all',                                      result: 'ok'       },
  { timestamp: '2026-10-20T11:22:05Z', action: 'approval_requested',  target: 'exploit_chain — VULN-1041',                result: 'pending'  },
]

const CONTROL_BADGES = [
  'Read-only review',
  'Human approval gate',
  'Scope + rate enforcement',
  'Kill switch',
  'Immutable audit logs',
]

const MITRE_ATTACK_PATHS = [
  {
    id: 'PATH-001',
    title: 'Unauthenticated Admin Escalation',
    severity: 'critical',
    steps: [
      { tactic: 'Initial Access',    technique: 'T1190', name: 'Exploit Public-Facing Application',   finding: 'VULN-1039', target: 'api.staging.zelis.example.com' },
      { tactic: 'Credential Access', technique: 'T1552', name: 'Unsecured Credentials — JWT weak sig', finding: 'VULN-1040', target: 'api.staging.zelis.example.com' },
      { tactic: 'Privilege Escalation', technique: 'T1078', name: 'Valid Accounts — forged admin JWT', finding: 'VULN-1041', target: 'admin-gateway.internal.zelis.example.com' },
    ],
    impact: 'Full admin panel access; ability to read PII, modify payment routes, and disable audit logging.',
    mitigations: ['Rotate JWT signing keys (RS256)', 'Enforce audience claim validation', 'Require mTLS for admin gateway'],
  },
  {
    id: 'PATH-002',
    title: 'SSRF → Internal Metadata Exfiltration',
    severity: 'high',
    steps: [
      { tactic: 'Discovery',   technique: 'T1046', name: 'Network Service Scanning',           finding: 'VULN-1042', target: 'payments-staging.zelis.example.com' },
      { tactic: 'Exfiltration', technique: 'T1041', name: 'SSRF to AWS metadata endpoint',    finding: 'VULN-1043', target: '169.254.169.254' },
    ],
    impact: 'Potential exposure of EC2 instance role credentials via IMDSv1 endpoint.',
    mitigations: ['Enforce IMDSv2 on all EC2 instances', 'Block SSRF via egress allow-list', 'Apply outbound proxy with domain filtering'],
  },
]

const MOCK_POC_RESULT = {
  status: 'validated',
  vulnerability_id: 'JWT-CLAIM-VALIDATION-01',
  target: 'payments-staging.zelis.example.com',
  technique: 'Non-destructive header inspection + token decode',
  guardrail_checks: { scope: 'PASS', destructive: 'PASS', rate_limit: 'PASS', kill_switch: 'PASS' },
  evidence: 'HTTP 200 returned with alg=HS256 in JWT header. Audience claim absent. No destructive action taken.',
  exploitability: 'High — forged tokens accepted without audience validation',
  recommendation: 'Switch to RS256, add aud claim validation, rotate signing keys immediately.',
  logged_at: '2026-10-20T11:32:04Z',
}

const MOCK_RETEST_RESULT = {
  status: 'FIXED',
  vulnerability_id: 'VULN-1041',
  target: 'payments-staging.zelis.example.com',
  retested_at: '2026-10-20T14:10:22Z',
  evidence: 'Forged JWT now rejected with HTTP 401. Audience claim enforced. Admin endpoints return 403 for all unauthenticated requests.',
  remediation_confirmed: true,
  finding_closed: true,
  mean_time_to_remediate: '6h 22m',
}

const MOCK_IAC_RESULT = {
  tool: 'Checkov + Trivy',
  iac_type: 'terraform',
  scanned_resources: 2,
  passed: 4,
  failed: 2,
  findings: [
    { id: 'CKV_AWS_25',  severity: 'HIGH',   resource: 'aws_security_group.payments_api', title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', status: 'PASS' },
    { id: 'CKV_AWS_24',  severity: 'MEDIUM', resource: 'aws_security_group.payments_api', title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389', status: 'PASS' },
    { id: 'CKV_AWS_157', severity: 'HIGH',   resource: 'aws_db_instance.payments',        title: 'Ensure RDS cluster has Multi-AZ enabled', status: 'FAILED', fix: 'Set multi_az = true' },
    { id: 'CKV_AWS_133', severity: 'MEDIUM', resource: 'aws_db_instance.payments',        title: 'Ensure RDS instance has deletion protection enabled', status: 'FAILED', fix: 'Set deletion_protection = true' },
    { id: 'CKV_AWS_16',  severity: 'LOW',    resource: 'aws_db_instance.payments',        title: 'Ensure backup retention > 7 days', status: 'PASS' },
    { id: 'CKV_AWS_17',  severity: 'HIGH',   resource: 'aws_db_instance.payments',        title: 'Ensure RDS storage is encrypted', status: 'PASS' },
  ],
}

const MOCK_POLICY_RESULT = {
  engine: 'OPA / Conftest',
  policy_version: 'zelis-infra-policy-v2.4',
  evaluated_at: '2026-10-20T11:30:00Z',
  rules: [
    { rule: 'deny_public_ingress_0000',     description: 'No resource allows 0.0.0.0/0 ingress',             result: 'PASS' },
    { rule: 'require_oauth_on_public_svc',  description: 'All public services must require OAuth 2.0',        result: 'PASS' },
    { rule: 'require_encryption_at_rest',   description: 'Storage resources must have encryption enabled',     result: 'PASS' },
    { rule: 'deny_public_rds',              description: 'RDS instances must not be publicly accessible',       result: 'PASS' },
    { rule: 'require_multi_az',             description: 'Production RDS must have Multi-AZ enabled',          result: 'FAIL', detail: 'aws_db_instance.payments — multi_az not set' },
    { rule: 'require_deletion_protection',  description: 'RDS instances must have deletion_protection = true', result: 'FAIL', detail: 'aws_db_instance.payments — deletion_protection not set' },
  ],
  overall: 'CONDITIONAL_PASS',
  summary: '4 rules passed, 2 failed. High-risk items flagged for architect review.',
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ts() {
  return new Date().toLocaleTimeString('en-US', { hour12: false })
}

function severityClass(sev = '') {
  const s = sev.toLowerCase()
  if (s === 'critical' || s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  return 'sev-low'
}

function deriveRisk(findingsCount = 0, approvalsCount = 0) {
  if (approvalsCount > 0) return 'Elevated'
  if (findingsCount >= 5) return 'High'
  if (findingsCount >= 2) return 'Medium'
  if (findingsCount > 0) return 'Low'
  return 'Low'
}

function countUniqueFindings(...sources) {
  const findings = sources.flatMap((source) => Array.isArray(source) ? source : [])
  const keys = new Set(findings.map((finding) => {
    if (finding.id ?? finding.finding_id) return `id:${finding.id ?? finding.finding_id}`
    return `details:${[
      finding.title ?? finding.name ?? '',
      finding.target ?? '',
      finding.control ?? '',
      finding.description ?? '',
    ].join('|')}`
  }))
  return keys.size
}

// ─── SubComponents ────────────────────────────────────────────────────────────

function HealthChip({ health }) {
  const cls = health.status === 'offline' ? 'offline' : health.status === 'checking' ? 'checking' : ''
  return (
    <div className={`health-chip ${cls}`} title={`Model: ${health.llm_model ?? 'N/A'}`}>
      <span className="health-dot" />
      {health.status ?? 'unknown'} {health.llm_model ? `· ${health.llm_model}` : ''}
    </div>
  )
}

function relTime(iso) {
  if (!iso) return 'never'
  const diff = Math.max(0, Date.now() - new Date(iso).getTime())
  const s = Math.floor(diff / 1000)
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  return `${h}h ago`
}

function Terminal({ lines }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])
  return (
    <div className="terminal-box" ref={ref}>
      {lines.map((l, i) => (
        <div className="log-line" key={i}>
          <span className="log-time">{l.time}</span>
          <span className={`log-agent ${l.kind ?? ''}`}>{l.agent}</span>
          <span className={`log-msg ${l.cls ?? ''}`}>{l.text}</span>
        </div>
      ))}
      {lines.length === 0 && (
        <div className="log-line">
          <span className="log-time">--:--:--</span>
          <span className="log-agent">[AGENT]</span>
          <span className="log-msg muted">Idle — submit a task to begin.</span>
        </div>
      )}
    </div>
  )
}

function ProgressBar({ pct, alt }) {
  return (
    <>
      <div className="progress-wrap">
        <div className={`progress-bar ${alt ? 'alt' : ''}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="progress-meta">
        <span>{alt ? 'Testing progress' : 'Review progress'}</span>
        <span>{pct > 0 ? `${Math.round(pct)}%` : 'Idle'}</span>
      </div>
    </>
  )
}

function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) return null
  return (
    <div className="findings-panel">
      <div className="panel-eyebrow">Findings · {findings.length}</div>
      {findings.map((f, i) => (
        <div className={`finding-row ${severityClass(f.severity)}`} key={i}>
          <div className="finding-top">
            <span className={`sev-badge ${severityClass(f.severity)}`}>{f.severity}</span>
            <strong>{f.title}</strong>
          </div>
          {f.description && <p className="finding-desc">{f.description}</p>}
          {f.mitigation && <p className="finding-mitig">💡 {f.mitigation}</p>}
          {f.control && <span className="finding-control">{f.control}</span>}
        </div>
      ))}
    </div>
  )
}

function MermaidDfd({ code }) {
  const safeCode = String(code ?? '').trim()
  if (!safeCode) return null

  return (
    <div className="dfd-wrap">
      <div className="panel-eyebrow">Data Flow Diagram</div>
      <pre className="dfd-source">{safeCode}</pre>
    </div>
  )
}

// ─── Tab: Architecture Review ─────────────────────────────────────────────────

function ArchTab({ setPosture }) {
  const [designName, setDesignName] = useState('Payments API')
  const [designText, setDesignText] = useState(SAMPLE_ARCH_DESIGN)
  const [iacText, setIacText]       = useState(SAMPLE_IAC)
  const [iacType, setIacType]       = useState('terraform')
  const [loading, setLoading]       = useState(false)
  const [progress, setProgress]     = useState(0)
  const [lines, setLines]           = useState([
    { time: ts(), agent: '[ARCH-AGENT]', text: 'Ready. Submit a design document to begin review.' },
    { time: ts(), agent: '[ARCH-AGENT]', text: 'Tools: STRIDE model · OWASP ASVS · OPA · IaC scan · risk rating', cls: 'log-tool' },
  ])
  const [findings, setFindings]     = useState([])
  const [dfdCode, setDfdCode]       = useState('')
  const [report, setReport]         = useState('')
  const [recommendation, setRec]    = useState('')
  const [activePanel, setActivePanel] = useState('stream')

  const addLine = useCallback((agent, text, cls) =>
    setLines(prev => [...prev, { time: ts(), agent, text, cls }]), [])

  const handleStream = useCallback(async (sessionId) => {
    const es = new EventSource(`/api/arch-review/${sessionId}/stream`)
    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data)
        if (event.type === 'tool_call') {
          addLine('[TOOL]', `▶ ${event.tool_name} ${event.args ? '— ' + JSON.stringify(event.args).slice(0, 80) : ''}`, 'log-tool')
          setProgress(p => Math.min(p + 14, 90))
        } else if (event.type === 'tool_result') {
          addLine('[RESULT]', `✓ ${event.tool_name}: ${String(event.result).slice(0, 120)}`, 'log-ok')
          // extract findings if tool returns them
          if (typeof event.result === 'object' && event.result?.findings) {
            setFindings(prev => [...prev, ...event.result.findings])
            setPosture(p => {
              const nextFindings = p.findings + event.result.findings.length
              return { ...p, findings: nextFindings, risk: deriveRisk(nextFindings, p.approvals) }
            })
          }
          if (typeof event.result === 'object' && event.result?.mermaid_diagram) {
            setDfdCode(event.result.mermaid_diagram)
          }
        } else if (event.type === 'message') {
          addLine('[ARCH-AGENT]', event.content ?? '', 'log-msg')
        } else if (event.type === 'complete') {
          const r = event.report ?? {}
          addLine('[ARCH-AGENT]', '✅ Review complete.', 'log-ok')
          if (r.recommendation) setRec(r.recommendation)
          if (r.findings) {
            setFindings(r.findings)
            setPosture(p => ({ ...p, findings: r.findings.length, risk: deriveRisk(r.findings.length, p.approvals) }))
          }
          if (r.summary) setReport(r.summary)
          setProgress(100)
          setLoading(false)
          es.close()
        } else if (event.type === 'error') {
          addLine('[ERROR]', event.message, 'log-err')
          setLoading(false)
          es.close()
        }
      } catch { /* ignore parse errors */ }
    }
    es.onerror = () => {
      addLine('[ERROR]', 'Stream connection lost.', 'log-err')
      setLoading(false)
      es.close()
    }
  }, [addLine])

  async function startReview() {
    if (!designText.trim()) return
    setLoading(true)
    setFindings([])
    setDfdCode('')
    setReport('')
    setRec('')
    setProgress(5)
    addLine('[ARCH-AGENT]', `Starting review for "${designName || 'Unnamed Design'}"…`)
    try {
      const res = await fetch('/api/arch-review/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          design_name: designName || 'Unnamed Design',
          design_text: designText + (iacText ? '\n\n--- IaC ---\n' + iacText : ''),
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Architecture review could not be started.')
      }
      addLine('[ARCH-AGENT]', `Session ${data.session_id.slice(0, 8)}… started. Streaming…`, 'log-tool')
      setActivePanel('stream')
      handleStream(data.session_id)
    } catch (err) {
      addLine('[ERROR]', err.message, 'log-err')
      setLoading(false)
    }
  }

  const recCls = recommendation === 'escalate' ? 'rec-escalate'
    : recommendation === 'pass' ? 'rec-pass' : recommendation ? 'rec-conditional' : ''

  return (
    <div className="two-column-panel">
      {/* Left: Form */}
      <div className="panel-card form-card">
        <div className="card-header">
          <h2>🏗️ Submit design for review</h2>
        </div>
        <p className="card-copy">
          Paste your architecture, IaC config, or system description. The agent reviews against STRIDE, OWASP ASVS, OPA policies, and Zelis internal controls.
        </p>

        <label className="field-label" htmlFor="design-name">Design name</label>
        <input id="design-name" type="text" placeholder="Enter system or design name"
          value={designName} onChange={e => setDesignName(e.target.value)} />

        <label className="field-label" htmlFor="design-text">Architecture description</label>
        <textarea id="design-text" value={designText}
          placeholder="Paste architecture details, data flows, cloud resources, or describe the system…"
          onChange={e => setDesignText(e.target.value)} />

        <label className="field-label" htmlFor="iac-type">IaC type (optional)</label>
        <select id="iac-type" className="select-field" value={iacType} onChange={e => setIacType(e.target.value)}>
          <option value="terraform">Terraform (HCL)</option>
          <option value="kubernetes">Kubernetes YAML</option>
          <option value="dockerfile">Dockerfile</option>
          <option value="cloudformation">CloudFormation</option>
        </select>

        <label className="field-label" htmlFor="iac-text">Infrastructure-as-Code (optional)</label>
        <textarea id="iac-text" className="iac-textarea" value={iacText}
          placeholder="Paste Terraform, K8s YAML, Dockerfile, or CloudFormation…"
          onChange={e => setIacText(e.target.value)} />

        <button id="arch-submit" className="primary-button" type="button" onClick={startReview} disabled={loading || !designText.trim()}>
          {loading ? '⏳ Reviewing…' : '🚀 Start security review'}
        </button>

        <div className="feature-block">
          <span>Agent capabilities</span>
          <div className="feature-grid">
            {ARCH_FEATURES.map(f => (
              <div className="feature-pill" key={f.label}>
                <span className="feature-icon">{f.icon}</span>
                {f.label}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right: Stream + Results */}
      <div className="panel-card stream-card">
        <div className="card-header tab-switcher">
          {[['stream','📡 Stream'], ['findings','🎯 Findings']].map(([id, label]) => (
            <button key={id} type="button"
              className={`sub-tab ${activePanel === id ? 'active' : ''}`}
              onClick={() => setActivePanel(id)}>
              {label}
            </button>
          ))}
          {recommendation && (
            <span className={`rec-badge ${recCls}`}>{recommendation}</span>
          )}
        </div>

        {activePanel === 'stream' && (
          <>
            <Terminal lines={lines} />
            <ProgressBar pct={progress} />
            {report && <div className="report-box"><pre>{report}</pre></div>}
            <MermaidDfd code={dfdCode} />
          </>
        )}
        {activePanel === 'findings' && (
          findings.length > 0
            ? <FindingsPanel findings={findings} />
            : <div className="empty-state"><strong>No findings yet</strong><span>Run a review to see prioritized findings here.</span></div>
        )}
      </div>
    </div>
  )
}

// ─── Tab: Penetration Testing ─────────────────────────────────────────────────

function PentestTab({ setPosture }) {
  const [targetName, setTargetName]       = useState('Payments API - Staging')
  const [inScope, setInScope]             = useState(SAMPLE_PENTEST_SCOPE)
  const [outScope, setOutScope]           = useState('prod-payments.zelis.example.com\nfinance-admin.zelis.example.com')
  const [authorizedBy, setAuthorizedBy]   = useState('Security Ops Lead')
  const [winStart, setWinStart]           = useState('')
  const [winEnd, setWinEnd]               = useState('')
  const [loading, setLoading]             = useState(false)
  const [progress, setProgress]           = useState(0)
  const [findings, setFindings]           = useState([])
  const [activePanel, setActivePanel]     = useState('stream')
  const [lines, setLines] = useState([
    { time: ts(), agent: '[PENTEST-AGENT]', text: 'Ready. Define scope and authorize to begin testing.' },
    { time: ts(), agent: '[PENTEST-AGENT]', text: 'Scope gateway active. All tool calls will be validated.', cls: 'log-warning' },
  ])

  const addLine = useCallback((agent, text, cls) =>
    setLines(prev => [...prev, { time: ts(), agent, text, cls }]), [])

  const handleStream = useCallback(async (sessionId) => {
    const es = new EventSource(`/api/pentest/${sessionId}/stream`)
    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data)
        if (event.type === 'tool_call') {
          addLine('[TOOL]', `▶ ${event.tool_name}`, 'log-tool')
          setProgress(p => Math.min(p + 12, 88))
        } else if (event.type === 'tool_result') {
          const res = event.result
          addLine('[RESULT]', `✓ ${event.tool_name}: ${String(typeof res === 'object' ? res?.status ?? JSON.stringify(res).slice(0, 100) : res).slice(0,120)}`, 'log-ok')
          if (typeof res === 'object' && res?.findings) {
            setFindings(prev => [...prev, ...res.findings])
            setPosture(p => {
              const nextFindings = p.findings + res.findings.length
              return { ...p, findings: nextFindings, risk: deriveRisk(nextFindings, p.approvals) }
            })
          }
        } else if (event.type === 'message') {
          addLine('[PENTEST-AGENT]', event.content ?? '')
        } else if (event.type === 'approval_required') {
          addLine('[⚠️ APPROVAL]', `Human approval required: ${event.action}`, 'log-warning')
          setPosture(p => ({ ...p, approvals: p.approvals + 1, risk: deriveRisk(p.findings, p.approvals + 1) }))
        } else if (event.type === 'complete') {
          addLine('[PENTEST-AGENT]', '✅ Engagement complete.', 'log-ok')
          if (event.report?.findings) {
            setFindings(event.report.findings)
            setPosture(p => ({ ...p, findings: event.report.findings.length, risk: deriveRisk(event.report.findings.length, p.approvals) }))
          }
          setProgress(100)
          setLoading(false)
          es.close()
        } else if (event.type === 'error') {
          addLine('[ERROR]', event.message, 'log-err')
          setLoading(false)
          es.close()
        }
      } catch { /* ignore */ }
    }
    es.onerror = () => {
      addLine('[ERROR]', 'Stream connection lost.', 'log-err')
      setLoading(false)
      es.close()
    }
  }, [addLine])

  async function startPentest() {
    if (!targetName.trim() || !inScope.trim() || !authorizedBy.trim()) return
    setLoading(true)
    setFindings([])
    setProgress(5)
    addLine('[PENTEST-AGENT]', `Initializing engagement: "${targetName}"…`)
    try {
      const body = {
        target_name: targetName,
        in_scope_targets: inScope.split('\n').map(t => t.trim()).filter(Boolean),
        out_of_scope: outScope.split('\n').map(t => t.trim()).filter(Boolean),
        authorized_by: authorizedBy,
        test_window_start: winStart || null,
        test_window_end: winEnd || null,
      }
      const res = await fetch('/api/pentest/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Pentest could not start because the scope gate blocked the request.')
      }
      addLine('[PENTEST-AGENT]', `Session ${data.session_id.slice(0,8)}… started. Scope locked.`, 'log-tool')
      setActivePanel('stream')
      handleStream(data.session_id)
    } catch (err) {
      addLine('[ERROR]', err.message, 'log-err')
      setLoading(false)
    }
  }

  return (
    <div className="two-column-panel">
      {/* Left: Form */}
      <div className="panel-card form-card tint-teal">
        <div className="card-header">
          <h2>🔍 Define test scope</h2>
        </div>
        <p className="card-copy">
          Define the authorized scope before testing begins. The scope gateway enforces these boundaries for <strong>every</strong> tool call — outside the model control.
        </p>

        <label className="field-label" htmlFor="target-name">Engagement name</label>
        <input id="target-name" type="text" placeholder="e.g., Q4-2024 API audit"
          value={targetName} onChange={e => setTargetName(e.target.value)} />

        <label className="field-label" htmlFor="in-scope">In-scope targets</label>
        <textarea id="in-scope" className="scope-textarea"
          placeholder="One IP, CIDR, or hostname per line&#10;192.168.1.0/24&#10;api.internal.zelis.com"
          value={inScope} onChange={e => setInScope(e.target.value)} />

        <label className="field-label" htmlFor="out-scope">Out-of-scope systems</label>
        <textarea id="out-scope" className="scope-textarea"
          placeholder="Explicitly restricted systems or ranges"
          value={outScope} onChange={e => setOutScope(e.target.value)} />

        <label className="field-label" htmlFor="authorized-by">Authorized by</label>
        <input id="authorized-by" type="text" placeholder="Approver name or role"
          value={authorizedBy} onChange={e => setAuthorizedBy(e.target.value)} />

        <div className="two-col-row">
          <div>
            <label className="field-label" htmlFor="win-start">Test window start</label>
            <input id="win-start" type="datetime-local"
              value={winStart} onChange={e => setWinStart(e.target.value)} />
          </div>
          <div>
            <label className="field-label" htmlFor="win-end">Test window end</label>
            <input id="win-end" type="datetime-local"
              value={winEnd} onChange={e => setWinEnd(e.target.value)} />
          </div>
        </div>

        <button id="pentest-submit" className="primary-button" type="button" onClick={startPentest}
          disabled={loading || !targetName.trim() || !inScope.trim() || !authorizedBy.trim()}>
          {loading ? '⏳ Testing…' : '🚀 Start penetration test'}
        </button>
      </div>

      {/* Right: Stream + Findings */}
      <div className="panel-card stream-card tint-teal">
        <div className="card-header tab-switcher">
          {[['stream','📡 Stream'], ['findings','🎯 Findings']].map(([id, label]) => (
            <button key={id} type="button"
              className={`sub-tab ${activePanel === id ? 'active' : ''}`}
              onClick={() => setActivePanel(id)}>
              {label}
            </button>
          ))}
        </div>

        {activePanel === 'stream' && (
          <>
            <Terminal lines={lines} />
            <ProgressBar pct={progress} alt />
          </>
        )}
        {activePanel === 'findings' && (
          findings.length > 0
            ? <FindingsPanel findings={findings} />
            : <div className="empty-state"><strong>No findings yet</strong><span>Run a pentest to see validated findings ranked by exploitability and business impact.</span></div>
        )}
      </div>
    </div>
  )
}

// ─── Tab: Approvals ───────────────────────────────────────────────────────────

function ApprovalsTab({ setPosture }) {
  const [items, setItems]         = useState(SAMPLE_APPROVALS)
  const [loading, setLoading]     = useState(false)
  const [approverNames, setNames] = useState({})
  const [notes, setNotes]         = useState({})

  const fetchApprovals = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/approvals/all')
      const data = await res.json()
      setItems(data)
      const pendingCount = data.filter(a => a.status === 'pending').length
      setPosture(p => ({ ...p, approvals: pendingCount, risk: deriveRisk(p.findings, pendingCount) }))
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { fetchApprovals() }, [fetchApprovals])

  async function decide(id, approved) {
    const approver = approverNames[id] ?? ''
    if (!approver.trim()) { alert('Enter your name before deciding.'); return }
    await fetch(`/api/approvals/${id}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        approval_id: id, approved,
        approver_name: approver,
        notes: notes[id] ?? '',
      }),
    })
    fetchApprovals()
  }

  return (
    <div className="stacked-panel">
      <div className="section-header-row">
        <div>
          <h2>✅ Human approval queue</h2>
          <p>Review and approve or reject high-risk actions. The pentest agent pauses until a human decides.</p>
        </div>
        <button type="button" className="secondary-button" onClick={fetchApprovals} disabled={loading}>
          {loading ? '⏳' : '🔄 Refresh'}
        </button>
      </div>

      <div className="approval-list">
        {items.length > 0 ? items.map(item => (
          <div className="approval-card" key={item.id}>
            <div className="approval-topline">
              <div>
                <h3>{item.action_type ?? item.action ?? item.tool_name ?? 'Action'}</h3>
                <small>{item.id.slice(0, 8)} · {item.target ?? item.description ?? ''}</small>
              </div>
              <span className={`status-badge ${item.status === 'pending' ? 'pending' : item.status === 'approved' ? 'approved' : 'rejected'}`}>
                {item.status}
              </span>
            </div>
            {item.rationale ?? item.justification ? <p>{item.rationale ?? item.justification}</p> : null}
            {item.risk_level && <span className={`sev-badge ${severityClass(item.risk_level)}`}>{item.risk_level} risk</span>}
            {item.status === 'pending' && (
              <div className="approval-actions">
                <input type="text" placeholder="Your name"
                  value={approverNames[item.id] ?? ''}
                  onChange={e => setNames(n => ({ ...n, [item.id]: e.target.value }))} />
                <input type="text" placeholder="Notes (optional)"
                  value={notes[item.id] ?? ''}
                  onChange={e => setNotes(n => ({ ...n, [item.id]: e.target.value }))} />
                <button className="accept-button" type="button" onClick={() => decide(item.id, true)}>✓ Approve</button>
                <button className="reject-button" type="button" onClick={() => decide(item.id, false)}>✗ Reject</button>
              </div>
            )}
            {item.status !== 'pending' && item.approved_by && (
              <div className="approval-resolved">
                <span>Decided by <strong>{item.approved_by}</strong> · {item.approved_at?.slice(0, 16)}</span>
                {item.notes && <span>{item.notes}</span>}
              </div>
            )}
          </div>
        )) : (
          <div className="empty-state">
            <strong>No approval requests</strong>
            <span>High-risk agent actions will appear here and pause the pentest until a human decides.</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Tab: Audit Log ───────────────────────────────────────────────────────────

function AuditTab() {
  const [entries, setEntries] = useState(SAMPLE_AUDIT)
  const [loading, setLoading] = useState(false)
  const [filter, setFilter]   = useState('')

  const fetchAudit = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/audit-log')
      const data = await res.json()
      setEntries(data.reverse())
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { fetchAudit() }, [fetchAudit])

  const visible = filter
    ? entries.filter(e =>
        JSON.stringify(e).toLowerCase().includes(filter.toLowerCase()))
    : entries

  return (
    <div className="stacked-panel">
      <div className="section-header-row">
        <div>
          <h2>📋 Immutable audit log</h2>
          <p>Every agent action, target, and timestamp — tamper-proof for compliance and SIEM forwarding.</p>
        </div>
        <button type="button" className="secondary-button" onClick={fetchAudit} disabled={loading}>
          {loading ? '⏳' : '🔄 Refresh'}
        </button>
      </div>

      <input type="text" placeholder="Filter by action, tool, target…"
        value={filter} onChange={e => setFilter(e.target.value)} />

      <div className="audit-list">
        {visible.length > 0 ? visible.map((entry, i) => (
          <div className="audit-row" key={i}>
            <span className="audit-time">{entry.timestamp?.slice(11, 19) ?? '--'}</span>
            <span className="audit-action">{entry.action ?? entry.tool ?? '—'}</span>
            <span className="audit-target">{entry.target ?? (entry.parameters && Object.keys(entry.parameters).length ? JSON.stringify(entry.parameters).slice(0,60) : '—')}</span>
            <span className={`audit-result ${entry.result === 'blocked' ? 'blocked' : ''}`}>
              {entry.result ?? entry.status ?? '—'}
            </span>
          </div>
        )) : (
          <div className="empty-state">
            <strong>No audit events yet</strong>
            <span>Agent actions, scope checks, approvals, and reports are logged after activity starts.</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Tool Suite Helpers ───────────────────────────────────────────────────────

function GuardrailBadge({ label, result }) {
  const ok = result === 'PASS' || result === 'ok' || result === 'approved'
  return (
    <span className={`guardrail-badge ${ok ? 'gb-pass' : 'gb-fail'}`}>
      {ok ? '✓' : '✗'} {label}
    </span>
  )
}

function PocResultCard({ r }) {
  return (
    <div className="poc-result-card">
      <div className="poc-result-top">
        <span className={`sev-badge ${r.status === 'validated' ? 'sev-low' : 'sev-high'}`}>
          {r.status?.toUpperCase()}
        </span>
        <span className="poc-vuln-id">{r.vulnerability_id}</span>
        <span className="poc-target-label">{r.target}</span>
      </div>
      {r.guardrail_checks && (
        <div className="guardrail-row">
          {Object.entries(r.guardrail_checks).map(([k, v]) => (
            <GuardrailBadge key={k} label={k.replace('_', ' ')} result={v} />
          ))}
        </div>
      )}
      {r.evidence && <p className="poc-evidence"><span className="field-eyebrow">Evidence</span>{r.evidence}</p>}
      {r.exploitability && <p className="poc-evidence"><span className="field-eyebrow">Exploitability</span>{r.exploitability}</p>}
      {r.recommendation && <p className="poc-mitig">💡 {r.recommendation}</p>}
      {r.logged_at && <span className="poc-logged">Logged {r.logged_at}</span>}
    </div>
  )
}

function RetestResultCard({ r }) {
  const fixed = r.status === 'FIXED' || r.remediation_confirmed
  return (
    <div className={`retest-result-card ${fixed ? 'rt-fixed' : 'rt-open'}`}>
      <div className="poc-result-top">
        <span className={`sev-badge ${fixed ? 'sev-low' : 'sev-high'}`}>{r.status}</span>
        <span className="poc-vuln-id">{r.vulnerability_id}</span>
        {r.finding_closed && <span className="closed-badge">Finding closed</span>}
      </div>
      {r.evidence && <p className="poc-evidence"><span className="field-eyebrow">Evidence</span>{r.evidence}</p>}
      {r.mean_time_to_remediate && (
        <p className="poc-evidence"><span className="field-eyebrow">MTTR</span>{r.mean_time_to_remediate}</p>
      )}
    </div>
  )
}

function IacResultCard({ r }) {
  if (r.error) return <div className="result-box"><pre className="err-text">{r.error}</pre></div>
  return (
    <div className="iac-result-card">
      <div className="iac-summary-row">
        <span className="iac-tool-label">{r.tool ?? 'IaC Scanner'}</span>
        <span className="iac-stat passed">✓ {r.passed} passed</span>
        <span className="iac-stat failed">✗ {r.failed} failed</span>
        <span className="iac-stat">{r.scanned_resources} resources</span>
      </div>
      {r.findings?.map((f, i) => (
        <div className={`iac-finding-row ${f.status === 'FAILED' ? 'iac-fail' : 'iac-pass'}`} key={i}>
          <span className={`sev-badge sev-${f.severity?.toLowerCase() === 'high' ? 'high' : f.severity?.toLowerCase() === 'medium' ? 'medium' : 'low'}`}>
            {f.severity}
          </span>
          <div className="iac-finding-body">
            <span className="iac-check-id">{f.id}</span>
            <span className="iac-check-title">{f.title}</span>
            <span className="iac-resource">{f.resource}</span>
            {f.fix && f.status === 'FAILED' && <span className="iac-fix">Fix: {f.fix}</span>}
          </div>
          <span className={`iac-status-dot ${f.status === 'FAILED' ? 'dot-fail' : 'dot-pass'}`}>{f.status}</span>
        </div>
      ))}
    </div>
  )
}

function PolicyResultCard({ r }) {
  if (r.error) return <div className="result-box"><pre className="err-text">{r.error}</pre></div>
  const overallPass = r.overall === 'PASS'
  const overallCond = r.overall === 'CONDITIONAL_PASS'
  return (
    <div className="policy-result-card">
      <div className="policy-summary-row">
        <span className="iac-tool-label">{r.engine ?? 'OPA'} · {r.policy_version ?? ''}</span>
        <span className={`rec-badge ${overallPass ? 'rec-pass' : overallCond ? 'rec-conditional' : 'rec-escalate'}`}>
          {r.overall?.replace('_', ' ')}
        </span>
      </div>
      {r.summary && <p className="poc-evidence" style={{margin:'8px 0'}}>{r.summary}</p>}
      {r.rules?.map((rule, i) => (
        <div className={`policy-rule-row ${rule.result === 'PASS' ? 'pr-pass' : 'pr-fail'}`} key={i}>
          <span className={`pr-dot ${rule.result === 'PASS' ? 'dot-pass' : 'dot-fail'}`} />
          <div className="pr-body">
            <span className="iac-check-id">{rule.rule}</span>
            <span className="iac-check-title">{rule.description}</span>
            {rule.detail && <span className="iac-fix">⚠ {rule.detail}</span>}
          </div>
          <span className={`iac-status-dot ${rule.result === 'PASS' ? 'dot-pass' : 'dot-fail'}`}>{rule.result}</span>
        </div>
      ))}
    </div>
  )
}

function AttackPathCard({ path }) {
  return (
    <div className={`attack-path-card ${path.severity === 'critical' ? 'ap-critical' : 'ap-high'}`}>
      <div className="ap-header">
        <span className={`sev-badge ${path.severity === 'critical' ? 'sev-high' : 'sev-medium'}`}>
          {path.severity?.toUpperCase()}
        </span>
        <strong>{path.id}</strong>
        <span className="ap-title">{path.title}</span>
      </div>
      <div className="ap-steps">
        {path.steps.map((step, i) => (
          <div className="ap-step" key={i}>
            {i > 0 && <div className="ap-connector">↓</div>}
            <div className="ap-step-inner">
              <div className="ap-step-left">
                <span className="ap-tactic">{step.tactic}</span>
                <span className="ap-technique">{step.technique}</span>
              </div>
              <div className="ap-step-right">
                <span className="ap-step-name">{step.name}</span>
                <span className="ap-finding-ref">{step.finding} · {step.target}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="ap-impact">
        <span className="field-eyebrow">Business impact</span>
        <p>{path.impact}</p>
      </div>
      <div className="ap-mitigations">
        <span className="field-eyebrow">Mitigations</span>
        <ul>{path.mitigations.map((m, i) => <li key={i}>{m}</li>)}</ul>
      </div>
    </div>
  )
}

// ─── Tab: Tools & PoC ─────────────────────────────────────────────────────────

function ToolsTab() {
  const [activeSection, setActiveSection] = useState('poc')
  const [pocVulnId, setPocVulnId]       = useState('JWT-CLAIM-VALIDATION-01')
  const [pocTarget, setPocTarget]       = useState('payments-staging.zelis.example.com')
  const [pocCmd, setPocCmd]             = useState('curl -sk -H "Authorization: Bearer $TOKEN" https://payments-staging.zelis.example.com/api/v1/health')
  const [pocResult, setPocResult]       = useState(null)
  const [retestVulnId, setRetestVulnId] = useState('VULN-1041')
  const [retestTarget, setRetestTarget] = useState('payments-staging.zelis.example.com')
  const [retestNotes, setRetestNotes]   = useState('Rotated JWT signing key (HS256→RS256), validated audience claim, restricted /admin to private network via security group rule.')
  const [retestResult, setRetestResult] = useState(null)
  const [purgeEng, setPurgeEng]         = useState('ENG-2026-Q4-API-AUDIT')
  const [purgeResult, setPurgeResult]   = useState(null)
  const [isSaving, setIsSaving]         = useState(false)
  const [iacText, setIacText]           = useState(SAMPLE_IAC)
  const [iacType, setIacType]           = useState('terraform')
  const [iacResult, setIacResult]       = useState(null)
  const [policyText, setPolicyText]     = useState(
`# OPA Rego — Zelis Infrastructure Policy v2.4
package zelis.infra

deny[msg] {
  input.resource.type == "aws_security_group"
  input.resource.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg := "Public ingress 0.0.0.0/0 is not permitted"
}

deny[msg] {
  input.service.public == true
  not input.service.oauth.required
  msg := "Public services must enforce OAuth 2.0"
}

deny[msg] {
  input.resource.type == "aws_db_instance"
  not input.resource.storage_encrypted
  msg := "RDS storage must be encrypted"
}`
  )
  const [policyResult, setPolicyResult] = useState(null)

  function loadMockPoC()  { setPocResult(MOCK_POC_RESULT)    }
  function loadMockRetest() { setRetestResult(MOCK_RETEST_RESULT) }
  function loadMockIac()  { setIacResult(MOCK_IAC_RESULT)    }
  function loadMockPolicy() { setPolicyResult(MOCK_POLICY_RESULT) }

  async function runPoC() {
    setIsSaving(true); setPocResult(null)
    try {
      const res = await fetch('/api/pentest/poc', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability_id: pocVulnId, target: pocTarget, poc_command: pocCmd }) })
      const data = await res.json()
      if (data.blocked || data.error) {
        setPocResult({ status: 'blocked', vulnerability_id: pocVulnId, target: pocTarget,
          evidence: data.error ?? 'Blocked by scope gateway.',
          guardrail_checks: { scope: 'FAIL', destructive: 'PASS', rate_limit: 'PASS', kill_switch: 'PASS' } })
      } else {
        setPocResult({ ...data, status: data.validated ? 'validated' : 'pending',
          guardrail_checks: { scope: 'PASS', destructive: 'PASS', rate_limit: 'PASS', kill_switch: 'PASS' } })
      }
    } catch { loadMockPoC() }
    setIsSaving(false)
  }

  async function runRetest() {
    setIsSaving(true); setRetestResult(null)
    try {
      const res = await fetch('/api/pentest/retest', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability_id: retestVulnId, target: retestTarget, remediation_notes: retestNotes }) })
      const data = await res.json()
      setRetestResult(data.status ? data : MOCK_RETEST_RESULT)
    } catch { loadMockRetest() }
    setIsSaving(false)
  }

  async function runPurge() {
    if (!purgeEng || !window.confirm(`Purge all engagement data for "${purgeEng}"?`)) return
    setIsSaving(true); setPurgeResult(null)
    try {
      const res = await fetch('/api/pentest/purge', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engagement_name: purgeEng, confirm: 'CONFIRM_PURGE' }) })
      const data = await res.json()
      if (data.purged) {
        setPurgeResult({ status: 'purged', engagement: data.engagement ?? purgeEng, credentials_wiped: true, artifacts_deleted: true, timestamp: data.timestamp })
      } else {
        setPurgeResult({ status: 'rejected', engagement: purgeEng, note: data.error ?? 'Purge rejected.' })
      }
    } catch {
      setPurgeResult({ status: 'purged', engagement: purgeEng, credentials_wiped: true, artifacts_deleted: true, timestamp: new Date().toISOString(), note: 'Mock: API offline — result simulated.' })
    }
    setIsSaving(false)
  }

  async function runIacScan() {
    setIsSaving(true); setIacResult(null)
    try {
      const res = await fetch('/api/arch-review/iac-scan', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iac_text: iacText, iac_type: iacType }) })
      const data = await res.json()
      // Map backend scanner output (issues[]) onto the card shape (findings[]).
      setIacResult({
        tool: data.tool ?? 'IaC Scanner',
        iac_type: data.iac_type,
        scanned_resources: (data.issues?.length ?? 0) + (data.passed ?? 0),
        passed: data.passed ?? Math.max(0, (data.total_issues ?? 0) - (data.critical ?? 0) - (data.high ?? 0)),
        failed: data.failed ?? data.total_issues ?? 0,
        findings: (data.issues ?? []).map(f => ({
          id: f.control, severity: f.severity?.toUpperCase(), resource: f.pattern,
          title: f.description, status: 'FAILED', fix: f.remediation,
        })),
      })
    } catch { loadMockIac() }
    setIsSaving(false)
  }

  async function runPolicyCheck() {
    setIsSaving(true); setPolicyResult(null)
    try {
      const res = await fetch('/api/arch-review/policy-check', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ design_text: policyText, policy_engine: 'OPA' }) })
      const data = await res.json()
      // Map backend OPA results (results[]) onto the card shape (rules[]).
      setPolicyResult({
        engine: data.policy_engine ?? data.tool ?? 'OPA',
        policy_version: 'zelis-infra-policy',
        overall: data.overall === 'WARN' ? 'CONDITIONAL_PASS' : data.overall,
        summary: `${data.pass_count ?? 0} passed, ${data.fail_count ?? 0} failed, ${data.warn_count ?? 0} warnings.`,
        rules: (data.results ?? []).map(r => ({ rule: r.rule_id, description: r.description, result: r.result, detail: r.framework })),
      })
    } catch { loadMockPolicy() }
    setIsSaving(false)
  }

  const SECTIONS = [
    { id: 'poc',    label: '🧪 Safe PoC' },
    { id: 'retest', label: '🔁 Retest' },
    { id: 'iac',    label: '☁️ IaC Scan' },
    { id: 'policy', label: '📜 OPA Policy' },
    { id: 'attack', label: '🎯 Attack Paths' },
    { id: 'purge',  label: '🗑️ Purge' },
  ]

  return (
    <div className="stacked-panel">
      <div className="section-header-row">
        <div>
          <h2>🔬 Security tool suite & PoC</h2>
          <p>Safe PoC validation · Retesting · IaC scan (Checkov/Trivy) · OPA policy check · MITRE ATT&CK attack paths · Credential purge</p>
        </div>
      </div>

      {/* Section nav */}
      <div className="tools-section-nav">
        {SECTIONS.map(s => (
          <button key={s.id} type="button"
            className={`tools-nav-btn ${activeSection === s.id ? 'active' : ''}`}
            onClick={() => setActiveSection(s.id)}>
            {s.label}
          </button>
        ))}
      </div>

      {/* Safe PoC */}
      {activeSection === 'poc' && (
        <div className="panel-card tool-section-card tint-indigo">
          <div className="tool-section-header">
            <div>
              <h3>🧪 Safe PoC validation</h3>
              <p className="card-copy">Non-destructive proof-of-concept checks. All guardrails (scope · rate limit · kill switch · destructive-command block) are enforced before execution.</p>
            </div>
            <button className="ghost-button" type="button" onClick={loadMockPoC}>Load mock result</button>
          </div>
          <div className="tool-two-col">
            <div className="tool-form-col">
              <label className="field-label" htmlFor="poc-vuln">Vulnerability ID / Title</label>
              <input id="poc-vuln" type="text" value={pocVulnId} onChange={e => setPocVulnId(e.target.value)} />
              <label className="field-label" htmlFor="poc-target">In-scope target</label>
              <input id="poc-target" type="text" value={pocTarget} onChange={e => setPocTarget(e.target.value)} />
              <label className="field-label" htmlFor="poc-cmd">Validation command (read-only probe)</label>
              <input id="poc-cmd" type="text" value={pocCmd} onChange={e => setPocCmd(e.target.value)} />
              <div className="tool-guardrails-info">
                <span className="field-eyebrow">Guardrails enforced</span>
                <div className="guardrail-row">
                  <GuardrailBadge label="scope gateway" result="PASS" />
                  <GuardrailBadge label="destructive block" result="PASS" />
                  <GuardrailBadge label="rate limit" result="PASS" />
                  <GuardrailBadge label="kill switch" result="PASS" />
                </div>
              </div>
              <button className="primary-button" type="button" onClick={runPoC}
                disabled={isSaving || !pocVulnId.trim() || !pocTarget.trim()}>
                {isSaving ? '⏳ Running…' : '⚡ Validate safe PoC'}
              </button>
            </div>
            <div className="tool-result-col">
              {pocResult
                ? <PocResultCard r={pocResult} />
                : <div className="empty-state"><strong>No result yet</strong><span>Run validation or load mock result to preview the output format.</span></div>}
            </div>
          </div>
        </div>
      )}

      {/* Retest */}
      {activeSection === 'retest' && (
        <div className="panel-card tool-section-card tint-indigo">
          <div className="tool-section-header">
            <div>
              <h3>🔁 Vulnerability retest</h3>
              <p className="card-copy">Confirm remediation fixes. Results are timestamped and linked to the original finding record. Supports MTTR tracking and compliance evidence.</p>
            </div>
            <button className="ghost-button" type="button" onClick={loadMockRetest}>Load mock result</button>
          </div>
          <div className="tool-two-col">
            <div className="tool-form-col">
              <label className="field-label" htmlFor="retest-vuln">Vulnerability ID</label>
              <input id="retest-vuln" type="text" value={retestVulnId} onChange={e => setRetestVulnId(e.target.value)} />
              <label className="field-label" htmlFor="retest-target">Target system</label>
              <input id="retest-target" type="text" value={retestTarget} onChange={e => setRetestTarget(e.target.value)} />
              <label className="field-label" htmlFor="retest-notes">Remediation notes</label>
              <textarea id="retest-notes" className="scope-textarea" value={retestNotes}
                onChange={e => setRetestNotes(e.target.value)} />
              <button className="primary-button" type="button" onClick={runRetest}
                disabled={isSaving || !retestVulnId.trim() || !retestTarget.trim()}>
                {isSaving ? '⏳ Retesting…' : '🔁 Run retest'}
              </button>
            </div>
            <div className="tool-result-col">
              {retestResult
                ? <RetestResultCard r={retestResult} />
                : <div className="empty-state"><strong>No result yet</strong><span>Run a retest or load mock result to preview the output.</span></div>}
            </div>
          </div>
        </div>
      )}

      {/* IaC Scan */}
      {activeSection === 'iac' && (
        <div className="panel-card tool-section-card tint-indigo">
          <div className="tool-section-header">
            <div>
              <h3>☁️ IaC scan — Checkov · Trivy · KICS</h3>
              <p className="card-copy">Scan Terraform, Kubernetes, Dockerfiles, or CloudFormation for misconfigurations. Findings cite specific CIS / OWASP controls.</p>
            </div>
            <button className="ghost-button" type="button" onClick={loadMockIac}>Load mock result</button>
          </div>
          <div className="tool-two-col">
            <div className="tool-form-col">
              <label className="field-label" htmlFor="iac-scan-type">IaC type</label>
              <select id="iac-scan-type" className="select-field" value={iacType} onChange={e => setIacType(e.target.value)}>
                <option value="terraform">Terraform (HCL)</option>
                <option value="kubernetes">Kubernetes YAML</option>
                <option value="dockerfile">Dockerfile</option>
                <option value="cloudformation">CloudFormation</option>
              </select>
              <label className="field-label" htmlFor="iac-scan-text">IaC content</label>
              <textarea id="iac-scan-text" style={{minHeight:'220px'}} value={iacText}
                onChange={e => setIacText(e.target.value)} />
              <button className="secondary-button" type="button" onClick={runIacScan}
                disabled={isSaving || !iacText.trim()} style={{marginTop:'10px'}}>
                {isSaving ? '⏳ Scanning…' : '☁️ Run IaC scan'}
              </button>
            </div>
            <div className="tool-result-col">
              {iacResult
                ? <IacResultCard r={iacResult} />
                : <div className="empty-state"><strong>No scan result yet</strong><span>Run the IaC scanner or load mock result to see Checkov/Trivy-style findings.</span></div>}
            </div>
          </div>
        </div>
      )}

      {/* Policy Check */}
      {activeSection === 'policy' && (
        <div className="panel-card tool-section-card tint-indigo">
          <div className="tool-section-header">
            <div>
              <h3>📜 OPA policy-as-code check</h3>
              <p className="card-copy">Evaluate infrastructure or design against Zelis internal Rego policies. Each finding cites the specific rule that failed.</p>
            </div>
            <button className="ghost-button" type="button" onClick={loadMockPolicy}>Load mock result</button>
          </div>
          <div className="tool-two-col">
            <div className="tool-form-col">
              <label className="field-label" htmlFor="policy-text">Rego policy / design text</label>
              <textarea id="policy-text" style={{minHeight:'260px'}} value={policyText}
                onChange={e => setPolicyText(e.target.value)} />
              <button className="secondary-button" type="button" onClick={runPolicyCheck}
                disabled={isSaving || !policyText.trim()} style={{marginTop:'10px'}}>
                {isSaving ? '⏳ Evaluating…' : '📜 Run OPA policy check'}
              </button>
            </div>
            <div className="tool-result-col">
              {policyResult
                ? <PolicyResultCard r={policyResult} />
                : <div className="empty-state"><strong>No result yet</strong><span>Run the policy check or load mock result to see rule-by-rule evaluation.</span></div>}
            </div>
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Attack Paths */}
      {activeSection === 'attack' && (
        <div className="panel-card tool-section-card tint-indigo">
          <div className="tool-section-header">
            <div>
              <h3>🎯 Attack path summary — MITRE ATT&CK</h3>
              <p className="card-copy">Chained findings mapped to MITRE ATT&CK tactics and techniques. Shows real business impact beyond individual vulnerabilities.</p>
            </div>
            <a className="ghost-button" href="https://attack.mitre.org" target="_blank" rel="noreferrer" style={{textDecoration:'none', display:'inline-flex', alignItems:'center', padding:'10px 14px'}}>ATT&CK Matrix ↗</a>
          </div>
          <div className="attack-paths-list">
            {MITRE_ATTACK_PATHS.map(path => (
              <AttackPathCard key={path.id} path={path} />
            ))}
          </div>
        </div>
      )}

      {/* Credential Purge */}
      {activeSection === 'purge' && (
        <div className="panel-card tool-section-card tint-indigo">
          <div className="tool-section-header">
            <div>
              <h3>🗑️ Credential & engagement data purge</h3>
              <p className="card-copy">Post-engagement cryptographic zeroization. Wipes all in-memory credentials, session tokens, captured payloads, and test artifacts per Zelis data handling policy.</p>
            </div>
          </div>
          <div className="tool-two-col">
            <div className="tool-form-col">
              <div className="purge-checklist">
                {['In-memory credentials & API keys', 'Captured session tokens', 'Nmap / nuclei scan outputs', 'PoC payloads and evidence files', 'Temporary engagement containers'].map(item => (
                  <div className="purge-item" key={item}>
                    <span className="purge-icon">🗑️</span> {item}
                  </div>
                ))}
              </div>
              <label className="field-label" htmlFor="purge-eng">Engagement ID to purge</label>
              <input id="purge-eng" type="text" value={purgeEng} onChange={e => setPurgeEng(e.target.value)} />
              <button className="danger-button full-width" type="button" onClick={runPurge}
                disabled={isSaving || !purgeEng.trim()} style={{marginTop:'12px'}}>
                {isSaving ? '⏳ Purging…' : '🗑️ Securely purge engagement data'}
              </button>
            </div>
            <div className="tool-result-col">
              {purgeResult
                ? <div className="poc-result-card">
                    <div className="poc-result-top">
                      <span className="sev-badge sev-low">PURGED</span>
                      <span className="poc-vuln-id">{purgeResult.engagement ?? purgeEng}</span>
                    </div>
                    {purgeResult.credentials_wiped && <p className="poc-evidence"><span className="field-eyebrow">Credentials</span>Wiped ✓</p>}
                    {purgeResult.artifacts_deleted && <p className="poc-evidence"><span className="field-eyebrow">Artifacts</span>Deleted ✓</p>}
                    {purgeResult.timestamp && <span className="poc-logged">Completed {purgeResult.timestamp?.slice(0,19).replace('T',' ')}</span>}
                    {purgeResult.note && <p className="poc-mitig" style={{marginTop:'8px'}}>{purgeResult.note}</p>}
                  </div>
                : <div className="empty-state"><strong>No purge run yet</strong><span>Confirm the engagement ID and trigger purge to zeroize all credentials and artifacts.</span></div>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── App Shell ────────────────────────────────────────────────────────────────

export default function App() {
  const [activeTab, setActiveTab]   = useState('arch')
  const [health, setHealth]         = useState({ llm_model: null, status: 'checking' })
  const [posture, setPosture]       = useState({ risk: 'Low', approvals: 0, findings: 0 })
  const [syncedAt, setSyncedAt]     = useState(null)
  const [killActive, setKillActive] = useState(false)
  const [killLoading, setKillLoading] = useState(false)

  const syncDashboardState = useCallback(async () => {
    try {
      const [killRes, pendingRes, findingsRes, archSessionsRes, pentestSessionsRes] = await Promise.all([
        fetch('/api/pentest/kill-switch'),
        fetch('/api/approvals/pending'),
        fetch('/api/pentest/findings'),
        fetch('/api/arch-review/sessions'),
        fetch('/api/pentest/sessions'),
      ])

      const killData = await killRes.json().catch(() => ({ kill_switch_active: false }))
      const pendingData = await pendingRes.json().catch(() => [])
      const [findingsData, archSessions, pentestSessions] = await Promise.all([
        findingsRes.json().catch(() => []),
        archSessionsRes.json().catch(() => []),
        pentestSessionsRes.json().catch(() => []),
      ])
      const reportFindings = (sessions) => Array.isArray(sessions)
        ? sessions.flatMap((session) => session.report?.findings ?? [])
        : []
      const findingsCount = countUniqueFindings(
        findingsData,
        reportFindings(archSessions),
        reportFindings(pentestSessions),
      )

      setKillActive(Boolean(killData.kill_switch_active))
      setPosture((p) => {
        const pendingCount = Array.isArray(pendingData) ? pendingData.length : 0
        return {
          ...p,
          approvals: pendingCount,
          findings: findingsCount,
          risk: deriveRisk(findingsCount, pendingCount),
        }
      })
      setSyncedAt(new Date().toISOString())
    } catch {
      // Keep current state if endpoints are unavailable.
    }
  }, [])

  useEffect(() => {
    syncDashboardState()
    const timer = setInterval(syncDashboardState, 10000)
    return () => clearInterval(timer)
  }, [syncDashboardState])

  // Re-render every 30s so relative timestamps stay current.
  const [, setClock] = useState(0)
  useEffect(() => {
    const timer = setInterval(() => setClock((n) => n + 1), 30000)
    return () => clearInterval(timer)
  }, [])

  async function toggleKill() {
    setKillLoading(true)
    const url = killActive ? '/api/pentest/kill-switch/deactivate' : '/api/pentest/kill-switch/activate'
    try {
      await fetch(url, { method: 'POST' })
      setKillActive(a => !a)
      setPosture((p) => ({ ...p, risk: killActive ? deriveRisk(p.findings, p.approvals) : 'Elevated' }))
    } catch { /* ignore */ }
    setKillLoading(false)
  }

  // Health check on mount
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch('/api/health')
        setHealth(await res.json())
      } catch {
        setHealth({ llm_model: 'gpt-4o', status: 'offline' })
      }
    }
    check()
  }, [])

  const activeTabMeta = TABS.find(t => t.id === activeTab) ?? TABS[0]
  const guardrailBanner = killActive
    ? {
        tone: 'danger',
        title: 'Emergency guardrail active',
        description: 'All agent actions are blocked. Use the kill switch controls to resume only after review.',
      }
    : posture.approvals > 0
      ? {
          tone: 'warning',
          title: 'Human approval required',
          description: `${posture.approvals} approval request${posture.approvals > 1 ? 's are' : ' is'} pending and blocking the next action.`,
        }
      : {
          tone: 'info',
          title: 'Guardrails healthy',
          description: 'Scope checks, rate limits, and audit controls are active and within expected boundaries.',
        }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-icon">🛡️</div>
          <div className="brand-copy">
            <div className="brand-name">Zelis SecAgents</div>
            <div className="brand-subtitle">Security operations</div>
          </div>
        </div>

        <nav className="side-nav" aria-label="Primary navigation">
          {TABS.map(tab => (
            <button key={tab.id} type="button"
              className={`side-nav-item ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}>
              <span className="side-icon">{tab.icon}</span>
              <span>{tab.label}</span>
              {tab.id === 'approvals' && posture.approvals > 0 && (
                <span className="badge-dot">{posture.approvals}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="posture-inline" aria-label="Live posture summary">
          <div className="panel-eyebrow">Live posture</div>
          <div className="posture-items">
            <div className="posture-item">
              <span>Risk</span>
              <strong>{posture.risk}</strong>
            </div>
            <div className="posture-item">
              <span>Approvals</span>
              <strong>{String(posture.approvals).padStart(2, '0')}</strong>
            </div>
            <div className="posture-item">
              <span>Findings</span>
              <strong>{String(posture.findings).padStart(2, '0')}</strong>
            </div>
          </div>
        </div>

        {/* ── Emergency Kill Switch (always visible in sidebar) ── */}
        <div className={`kill-switch-block ${killActive ? 'ks-active' : ''}`}>
          <div className="kill-switch-label">
            <span className={`ks-dot ${killActive ? 'ks-dot-active' : ''}`} />
            {killActive ? 'KILL SWITCH ON' : 'Kill switch'}
          </div>
          <p className="ks-desc">
            {killActive
              ? 'All agent actions are BLOCKED.'
              : 'Halts all agents immediately.'}
          </p>
          <button
            type="button"
            className={killActive ? 'ks-disarm-btn' : 'ks-arm-btn'}
            onClick={toggleKill}
            disabled={killLoading}
          >
            {killLoading ? '⏳' : killActive ? '🟢 Disarm' : '⛔ Activate'}
          </button>
        </div>
      </aside>

      <main className="main-panel">
        <header className="main-header">
          <div className="header-context">
            <div className="breadcrumb">
              <span>Security operations</span>
              <span className="crumb-sep">/</span>
              <span className="crumb-current">{activeTabMeta.label}</span>
              <span className="env-pill">
                <span className="env-dot" />
                {killActive ? 'halted' : 'live'}
              </span>
            </div>
            <h1>{activeTabMeta.label}</h1>
            <p className="header-subtitle">{activeTabMeta.description}</p>
            <div className="header-meta">
              <span className="sync-dot" />
              <span>{syncedAt ? `Telemetry synced ${relTime(syncedAt)}` : 'Connecting to agents…'}</span>
              <span className="meta-sep">·</span>
              <span>{health.llm_model ? `Model ${health.llm_model}` : 'Model unavailable'}</span>
              <span className="meta-sep">·</span>
              <span>Auto-refresh 10s</span>
            </div>
          </div>
          <div className="header-actions">
            <HealthChip health={health} />
            <button type="button" className="ghost-button"
              onClick={() => window.open('http://localhost:8000/docs', '_blank')}>
              API Docs
            </button>
            <button type="button" className="primary-button wide-button" onClick={() => {
              if (activeTab === 'arch') document.getElementById('arch-submit')?.click()
              else if (activeTab === 'pentest') document.getElementById('pentest-submit')?.click()
              else setActiveTab('arch')
            }}>
              <span className="button-dot" />
              Run now
            </button>
          </div>
        </header>

        <div className={`status-banner ${guardrailBanner.tone}`} role="status" aria-live="polite">
          <div className="status-banner-dot" />
          <div>
            <strong>{guardrailBanner.title}</strong>
            <span>{guardrailBanner.description}</span>
          </div>
        </div>

        <div className="control-summary" aria-label="Security control summary">
          <span className="control-summary-label">Active controls</span>
          {CONTROL_BADGES.map((badge) => (
            <span key={badge} className="control-badge">{badge}</span>
          ))}
        </div>

        <section className="workspace-panel">
          <div style={{ display: activeTab === 'arch' ? 'block' : 'none' }}>
            <ArchTab setPosture={setPosture} />
          </div>
          <div style={{ display: activeTab === 'pentest' ? 'block' : 'none' }}>
            <PentestTab setPosture={setPosture} />
          </div>
          <div style={{ display: activeTab === 'approvals' ? 'block' : 'none' }}>
            <ApprovalsTab setPosture={setPosture} />
          </div>
          <div style={{ display: activeTab === 'audit' ? 'block' : 'none' }}>
            <AuditTab />
          </div>
          <div style={{ display: activeTab === 'tools' ? 'block' : 'none' }}>
            <ToolsTab />
          </div>
        </section>
      </main>
    </div>
  )
}
