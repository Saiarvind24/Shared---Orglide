# ORGLIDE — Platform Intelligence & Positioning Audit

> Complete, codebase-grounded discovery document for the ORGLIDE website,
> enterprise positioning, and launch strategy. **Every claim below is traceable
> to actual code** (75 JPA models, 41 backend services, 34 controllers, a
> FastAPI AI microservice, 27 frontend surfaces, and the Phase 11–12 platform
> layer). Where something is *scaffolding* or *not yet proven*, it says so.

---

## SECTION 1 — PLATFORM UNDERSTANDING

**What ORGLIDE actually is:** an **AI-native compliance & audit operations
platform**. It is the system of record + system of action for running audits:
modeling frameworks as audits → sections → controls (requirements), collecting
and reviewing evidence, enforcing approval workflows, and proving the whole
history is tamper-evident — with an AI layer that reads documents, matches them
to requirements, scores readiness, and surfaces organizational risk.

**Category:** *Compliance Operating System / Audit Operations Platform* — not
task management. Task/assignment primitives exist, but they're the substrate for
compliance execution, not the product.

**Business problem it solves:** compliance and audit prep today lives in
spreadsheets, shared drives, and email threads — no defensible trail, no AI
assist, no real-time coordination, no operational visibility. ORGLIDE turns that
into a single, auditable, AI-assisted workspace.

**What makes it unique (grounded):**
1. **Tamper-evident audit trail** — per-tenant SHA-256 **hash-chained** audit
   log (`AuditChainEntry`, `IntegrityScanner`, `IntegrityAlert`) that's actively
   re-verified on a schedule. This is a genuinely uncommon, defensible feature.
2. **Real document intelligence, not a chatbot bolt-on** — a dedicated FastAPI
   service extracts text (pdfplumber + Tesseract OCR + python-docx), runs
   requirement matching, compliance review/readiness scoring, and cross-document
   similarity/version-diff, all grounded in the org's own data via **pgvector
   hybrid retrieval**.
3. **Operational maturity rarely seen at this stage** — orchestration spine,
   degraded-mode throttling, DLQ + event replay, observability, DR drills,
   supply-chain-gated deploys (Phases 7/11).

**Technical strengths:** Spring Boot 3.2 / Java 17 backend, React 18 SPA,
PostgreSQL + Flyway-managed schema, STOMP/WebSocket realtime, optional Kafka
event bus, a separate Python AI service, pgvector embeddings.

**Operational strengths:** Prometheus/Grafana/Loki/Alertmanager/Sentry, error
taxonomy, automated restore drills, provenance + cosign-signed releases, manual
production promotion gates.

**Architectural strengths:** clean service/controller/model layering, tenant
context + permission engine, event-driven AI orchestration with idempotency +
backpressure, resilience (degraded mode, stuck-job recovery, retry escalation).

---

## SECTION 2 — FEATURE INVENTORY (categorized, codebase-verified)

### Employee features
- **Workspace + tasks** (`EmployeeWorkspace`, `TaskService`, `Task`) — assigned
  compliance work, statuses, activity timeline. *Value:* clear ownership.
- **Employee AI Copilot** (`EmployeeCopilot`, `EmployeeAiService`,
  `RequirementExplanationService`) — plain-language task/requirement
  explanations, pre-submission **quality checks** (`SubmissionQualityService`),
  upload guidance, rejection-recovery help. *Value:* gets first-time submissions
  right; reduces reviewer churn.
- **Smart nudges** (`SmartNudgeService`, `EmployeeNudge`) — AI-generated nudges
  on at-risk tasks. **Employee memory** (`EmployeeAiMemory`) for context.
- **Evidence upload** (`DocumentService`, versioned, attributed).
- **Realtime chat + presence** (`ChatMessage`, `PresenceService`, STOMP).

### Manager features
- **Manager view + analytics** (`ManagerView`, `AnalyticsService`) — workload,
  advanced aggregations, team performance.
- **Evidence review + approval workflow** (`AuditService`, `EvidenceStatus`:
  submit → review → approve/reject/refine).
- **Calendar** (`CalendarController`) — unified tasks + evidence expiries +
  review deadlines.
- **Compliance overview** (`ComplianceOverviewController`) — posture + scores.

### Admin features
- **Identity lifecycle** (`AuthService`) — invite → activation token → OTP →
  password; suspend/reactivate; sessions + "sign out all".
- **RBAC** (`PermissionEngine`, `@RequirePermission`, `Permission`, `Role`) with
  a **permission audit** trail (`PermissionAudit`).
- **Workspace access management** (invites, roles) in Settings.

### Platform Ops (admin/operator)
- **Platform Operations Center** (`PlatformOperationsController`) — worker fleet
  map, queue intelligence, degraded mode, infrastructure incidents.
- **System Observability Center** (`SystemObservabilityCenter`) — metrics,
  health scoring, tenant operational pressure.
- **Production Health Center** (`/ops-health`) — DB/mail/storage/realtime/
  backup/restore-drill health + incident signals.

### AI systems — see Section 3.

### Compliance systems
- **Audit model** (`Audit`/`AuditSection`/`AuditControl`) framework-agnostic.
- **Tamper-evident audit trail** (`AuditChainEntry` hash chain + `IntegrityScanner`).
- **Evidence lifecycle + comments** (`EvidenceComment`, `DocumentComplianceReview`).
- **Governance** (`GovernancePolicy`, `GovernanceWorkflowRequest`, `LegalHold`,
  `RetentionRule`) — policy + workflow orchestration, legal holds, retention.
- **Document security** (`DocumentFingerprint`, `DocumentLineageLink`,
  `DocumentAccessToken`, secure preview sessions).

### Automation systems
- **Automation rules** (`AutomationRule`/`Condition`/`Action`, `AutomationEngine`)
  — IF condition → THEN action (auto-escalate, notify, flag). *Value:*
  policy-as-rules without code.

### Support systems
- **Support ticket pipeline** (`SupportTicket`/`Reply`, `SupportService`) —
  lifecycle, threaded replies, branded emails. **FAQ Center** + **Support
  Center** (Phase 12).

### Deployment systems — see Section 5.
### Observability / Security / Recovery / Operational — see Section 5.

---

## SECTION 3 — AI CAPABILITIES (accurate, no buzzwords)

ORGLIDE runs a **dedicated AI microservice** (FastAPI, `ai-service/`) behind the
Spring backend — the frontend never touches LLMs directly. Providers: **Anthropic
+ OpenAI**. Grounding: **pgvector** hybrid retrieval over the org's own audits,
controls, and evidence (`AiIndexingService` backfills the index).

**Concrete AI capabilities (each maps to real code):**
1. **Document analysis** (`analyzer.py`, `AiDocumentAnalysis`) — extracts text
   from PDF/scanned-image(OCR)/DOCX and analyzes evidence.
2. **Requirement matching** (`matcher.py`, `AiRequirementMatch`) — suggests which
   control/requirement an uploaded document satisfies, with confidence + reasons;
   accepting re-files it automatically.
3. **Compliance review copilot** (`reviewer.py`, `DocumentComplianceReview`) —
   readiness score, quality checks, risk flags, recommend (approve / needs
   refinement / reject). **Human makes the final call** — AI is advisory.
4. **Compliance memory** (`similarity.py`, `ComplianceMemoryRecord`) —
   cross-document similarity + version-diff (what changed since last time).
5. **Grounded chat copilot** (`chat_engine.py`, SSE streaming) — RAG Q&A over the
   workspace with cited sources; semantic search + follow-ups.
6. **Audit intelligence** (`AuditIntelligenceService`, snapshots) — org health,
   risk feed, department heatmap, trends, forecast.
7. **Organizational memory + strategic reasoning** (`OrganizationalMemoryService`,
   `StrategicReasoningService`, `RecurringPattern`, `Intervention`) — recurring/
   chronic patterns, interventions + effectiveness.
8. **Executive briefings** (`OrgBriefingService`, `OrgBriefing`) — generated
   leadership briefings + history.
9. **Risk watcher + signal correlation** (`RiskWatcherService`,
   `SignalCorrelationEngine`, `OperationalSignal`) — live operational signals
   and correlated risk clusters.
10. **AI governance + cost control** (`AiCostGovernanceEngine`,
    `TenantAiBudget`, `AiThrottlingService`, `ModelPerformanceIntelligence`,
    `AiOverrideRecord`, `AiTraceRecord`, `AiUsageEvent`) — per-tenant AI budgets,
    throttling, model performance, traceability, human-override records.

**Positioning truth:** ORGLIDE's AI is **operational and grounded** (reads *your*
documents, cites *your* sources, governs *its own* cost/usage) — not a generic
"chat with your data" wrapper. **Caveat:** it requires API keys + the AI service
running; quality depends on the configured LLM; AI output is advisory by design.

---

## SECTION 4 — COMPLIANCE + GOVERNANCE POSITIONING

- **Audit workflows:** model any framework (SOC 2, ISO 27001, internal, custom)
  as sections + controls; assign owners; collect + version evidence; submit →
  review → approve/reject/refine.
- **Governance systems:** `GovernancePolicy`, `GovernanceWorkflowRequest`,
  approval orchestration, **legal holds**, **retention rules**.
- **Evidence systems:** versioned documents, fingerprinting, lineage links,
  secure access tokens + preview sessions, evidence-level comments/threads.
- **Operational tracking + escalation:** automation rules auto-escalate/flag;
  reminders (`ReminderService`); notifications across channels.
- **Resilience as a compliance asset:** the **tamper-evident hash-chained audit
  trail** + integrity scanner is the centerpiece — "you can prove the record
  wasn't altered."

**Public positioning:** *"The compliance operating system with a defensible,
AI-assisted audit trail."* Lead with **defensibility** (tamper-evidence) +
**AI-assisted evidence review** — those are the differentiators.

---

## SECTION 5 — ENTERPRISE INFRASTRUCTURE AUDIT

All real and CI-green (Phases 11.1–11.8):
- **CI/CD:** ci-backend, ci-frontend, ci-cypress, ci-docker, ci-migrations,
  ci-security, ci-dr-drill — GitHub Actions, all green.
- **Migrations:** Flyway, baseline-on-migrate, V1→V4, `ddl-auto=validate` in prod,
  CI-validated against ephemeral Postgres.
- **Deployment gating:** `prod-readiness` + `deploy-production` — provenance
  verify + cosign signature verify + CI-success + CRITICAL-scan + **manual
  Environment approval**. No auto-prod.
- **Observability:** Prometheus + Grafana + Loki + Promtail + Alertmanager +
  cAdvisor; Micrometer `/actuator/prometheus`; Sentry (front + back), unified
  `ErrorCategory` taxonomy, structured logs with correlation IDs.
- **Backups + DR:** containerized nightly pg_dump + uploads tar, retention,
  offsite (rclone), GPG encryption, **automated restore drills** (`drill-restore.sh`,
  scheduled + CI), recovery-SLA metrics.
- **Supply chain:** SBOM (CycloneDX), build provenance attestations, cosign
  keyless signing, immutable `sha-` tags, Trivy image + dependency scanning.
- **Health + rollback:** `/api/health`, `/api/ops/health`, release correlation,
  documented gated rollback.

**Positioning truth:** the *engineering* is legitimately enterprise-grade. **The
honest caveat (critical):** it is **CI-verified and locally validated, not yet
run in production** — see Section 11.

---

## SECTION 6 — WEBSITE CONTENT EXTRACTION

- **Homepage:** hero — *"The compliance operating system. Defensible audits,
  AI-assisted evidence, real-time control."* Three pillars: Defensible Trail ·
  AI Document Intelligence · Operational Visibility. Social-proof placeholder.
- **Features:** Audits & Controls · Evidence Lifecycle · Approval Workflows ·
  Automation Rules · Realtime Collaboration · Calendar/Deadlines · Analytics.
- **AI page:** "Grounded, governed AI." Requirement matching, compliance review
  copilot, grounded chat with citations, audit intelligence, AI cost governance.
  Emphasize *human-in-the-loop* + *grounded in your data*.
- **Infrastructure/Security page:** tamper-evident hash-chained trail, RBAC +
  permission audit, document security (fingerprint/lineage/access tokens),
  encryption, supply-chain-gated releases, SBOM + signed images.
- **Observability page:** real metrics/logs/alerts; Production Health Center
  screenshot; "we monitor ourselves the way we expect enterprises to."
- **Compliance page:** framework-agnostic modeling; legal holds + retention;
  defensible evidence chain.
- **Support page:** ticketing + SLA + FAQ + Support Center.
- **Pricing:** *"Contact us"* / waitlist (do NOT publish tiers yet — billing
  doesn't exist).
- **Enterprise trust section:** DR drills, backups, provenance, gated deploys —
  framed honestly as "engineering practices," not certifications.

---

## SECTION 7 — FAQ INVENTORY (enterprise-grade, realistic)

**Platform:** What is ORGLIDE? · What frameworks does it support? (any —
section/control model) · Is it task management? (no — compliance ops) · Does it
replace our auditor? (no — it prepares + proves).
**AI:** Does AI make decisions? (advisory; human approves) · Is my data sent to
train models? (no) · Which models? (Anthropic/OpenAI, configurable) · Is AI
grounded in our data? (yes — pgvector retrieval over your workspace) · Can we
cap AI cost? (yes — per-tenant budgets + throttling).
**Compliance/Audit:** How is the audit trail defensible? (SHA-256 hash chain,
continuously re-verified) · Can records be altered silently? (no — integrity
scanner alerts) · Legal holds / retention? (yes).
**Security:** RBAC? (yes, with permission audit) · Encryption? · Session
management / sign-out-all? (yes) · How are documents protected? (fingerprint,
lineage, access tokens, secure preview).
**Deployment/Data:** Where does it run? (your infra / single-tenant deploy
today) · Backups + recovery? (nightly + tested restore drills) · Data residency?
(deploy-controlled).
**Observability/Onboarding/Governance:** Health visibility? (Production Health
Center) · How do we onboard a team? (invite + activation + OTP) · Approval
workflows? (configurable). 
*(Map these into the existing `/help/faq` categories.)*

---

## SECTION 8 — PRODUCT POSITIONING

**Competes with / replaces:** compliance operating systems & audit-management
platforms (Vanta, Drata, Secureframe, Hyperproof, AuditBoard) — **but** ORGLIDE's
distinct angle is the **tamper-evident trail + grounded document-intelligence
copilot + deep operational/observability layer**, not just questionnaire
automation. Adjacent framings: governance/GRC platform, operational intelligence
for compliance.

**Do NOT position as:** task manager, generic AI chatbot, or a Notion/Asana
template. Lead with *defensible compliance operations*.

**One-liner:** *"ORGLIDE is the AI-native compliance operating system — run
audits, prove evidence, and defend the trail."*

---

## SECTION 9 — VISUAL POSITIONING

Grounded in the actual product UI (premium dark glassmorphic system, accent
emerald `#10b981`, frosted layered cards, design-token theming dark/light/gray/
glass):
- **Visual direction:** quiet enterprise premium — deep dark canvas, frosted
  glass cards, emerald accent, generous spacing, restrained gradients. Mirror
  the product so the site feels like the app.
- **Motion:** subtle, purposeful (the app already uses spring/ease tokens +
  reduced-motion support) — no gamer neon, no over-glow.
- **Storytelling:** "factory floor" credibility — show the real Production Health
  Center, audit trail, AI review verdict. Screens, not stock art.
- **Tone:** confident, precise, security-aware. Trust via specifics (hash chain,
  restore drills, signed releases), not adjectives.
- **Hierarchy:** outcome headline → 3 pillars → proof (screens) → trust → CTA.

---

## SECTION 10 — WEBSITE ARCHITECTURE (sitemap)

```
/                      Home (hero, 3 pillars, proof, trust, CTA)
/product
  /audits              Audits & controls, evidence lifecycle, approvals
  /ai                  Document intelligence, copilot, audit intelligence, AI governance
  /automation          Rules engine
  /collaboration       Realtime, presence, comments, calendar
/security              Tamper-evident trail, RBAC, doc security, encryption
/infrastructure        CI/CD, backups, DR drills, supply-chain, signed releases
/observability         Metrics/logs/alerts, Production Health Center
/compliance            Framework-agnostic, legal holds, retention, defensibility
/customers (later)     Case studies (placeholder until real users)
/pricing               "Contact us" / waitlist (no tiers yet)
/faq                   Enterprise FAQ (mirror in-app /help/faq)
/support               Ticketing + SLA + status
/trust                 Security + engineering practices (honest)
/company /about /contact
/login  →  app
```
**Conversion flow:** Home → pillar deep-dive → /security or /ai (the
differentiators) → /trust → Contact/Demo. Nav: Product ▾, Security,
Infrastructure, Compliance, Pricing, Docs, Login + "Book a demo".

---

## SECTION 11 — COMMERCIAL READINESS (brutally honest)

**Strong enough to market proudly:**
- The **tamper-evident audit trail** + integrity scanning — genuine, uncommon.
- **Grounded AI document intelligence** (matching, review, citations) — real,
  not a wrapper.
- **Realtime collaboration** + the full audit/evidence/approval workflow.
- The **engineering practices** (CI/CD, migrations, backups + tested restore
  drills, observability, signed/provenanced releases) — as *practices*.

**Still startup-stage / do NOT market aggressively:**
- **Multi-tenancy is not hardened** — the platform defaults to a single
  organization (`orglide.organization.default-id=1`); tenant isolation needs
  real hardening + testing before claiming "multi-tenant SaaS."
- **Never run in production** — no live deployment, no real users, no load. The
  whole stack is CI-verified + locally validated only. Don't claim uptime/SLAs.
- **No HA** — single-instance Postgres/backend/observability; no failover.
- **No security certification** — no SOC 2 / ISO cert (ironic for a compliance
  tool); say "built to support your compliance," not "we are certified."
- **No billing/commercial layer**, no pen test, no published pricing.
- Minor: 2 Cypress tests skipped; AI needs keys + the service running.

**Claims that ARE justified:** "tamper-evident audit trail," "AI-assisted
evidence review grounded in your data," "tested disaster recovery,"
"supply-chain-secured releases," "real-time compliance workspace."

**Claims to AVOID:** "enterprise-proven," "SOC 2 certified," "99.9% uptime,"
"battle-tested at scale," "fully multi-tenant," "trusted by [N] companies."

**What customers would realistically trust today:** a design-partner / early-
access pilot on a single-tenant deployment — not a self-serve enterprise SaaS.

---

## SECTION 12 — FINAL STRATEGIC ANALYSIS

**Strongest differentiators:**
1. Tamper-evident, continuously-verified audit trail (defensibility).
2. Grounded, governed AI document intelligence (matching + review + citations +
   cost governance) — a real moat vs. checklist tools.
3. Unusually deep operational/observability/DR engineering for the stage.

**Biggest technical strengths:** the AI microservice + pgvector grounding; the
event-driven orchestration spine with idempotency/backpressure/DLQ; the
hash-chain integrity system.

**Biggest operational strengths:** real observability + tested restore drills +
gated, signed, provenanced deploys.

**Biggest commercial gaps:** multi-tenancy hardening, a real production
deployment + first customers, HA, security certification, billing.

**Biggest website opportunities:** *show the real thing* — Production Health
Center, AI review verdict, the audit hash chain. Specifics build trust faster
than adjectives for a security buyer.

**Strongest enterprise positioning angle:** *"Defensible, AI-assisted compliance
operations — with engineering rigor you can audit."*

**Strongest investor angle:** *"AI-native compliance OS with a defensibility moat
(tamper-evident trail) + grounded AI + production-grade platform engineering
already built — the remaining work is go-to-market and multi-tenant scale, not
core platform."*

**Strongest customer angle:** *"Stop running audits in spreadsheets. ORGLIDE
gives you one workspace where evidence is reviewed by AI, approvals are enforced,
and the trail can't be quietly changed."*

---

### Honest one-paragraph summary
ORGLIDE is a real, deep **AI-native compliance operating system** — a defensible
hash-chained audit trail, a grounded document-intelligence AI layer, real-time
collaboration, and genuinely enterprise-grade platform engineering (CI/CD,
migrations, backups + tested DR, observability, signed/gated deploys). The
*platform* is far beyond MVP. What it is **not yet** is a *commercially deployed,
multi-tenant, certified SaaS*: it has never run in production, defaults to a
single org, has no HA/billing/cert, and no real users. Market the **capabilities
and engineering rigor proudly and specifically; market the maturity honestly**
(early access / design-partner, not "enterprise-proven").
