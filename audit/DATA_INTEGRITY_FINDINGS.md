# Data Integrity Findings

**Project:** taskboard
**Date:** 2026-05-13
**Scope:** invariants that the system *should* enforce on its data but currently does not — at the database, application, or domain layer.
**Posture:** the codebase has very few constraints beyond foreign keys. Almost every domain invariant is unenforced or enforced inconsistently. The [IDOR](IDOR_AND_HASH_LEAK_AUDIT.md) and [cross-project assignee](MASS_ASSIGNMENT_AUDIT.md) bugs are two visible instances of the same underlying pattern; this report enumerates the rest.

---

## 1. Executive summary

A data-integrity invariant is a property that **must hold across every state the system can reach**. The strongest place to enforce one is the database (so it survives any code path, including direct SQL, direct Prisma, future endpoints, and bugs in current ones). The second-best place is a domain entity that wraps construction/mutation. This project does **neither** for most of its invariants — relying instead on whatever the current route handler happens to check.

The audit reports already documented two breaches:

- **D1 (≙ [A1 IDOR](IDOR_AND_HASH_LEAK_AUDIT.md))** — any authenticated user can mutate any task. Result: rows are written by parties the model does not recognise as having authority.
- **D2 (≙ [B1 Cross-project assignee](MASS_ASSIGNMENT_AUDIT.md))** — `tasks.assignee_id` can point at a user who is not a member of `tasks.project_id`. The domain invariant "an assignee is a project member" is not held by either Prisma, Zod, or the application.

Below are the **integrity gaps not yet covered** by the existing reports. Each one is exploitable either through current API surface, a small extension of it, or as a latent corruption waiting on a future endpoint.

---

## 2. Summary table

| # | Invariant the system should hold | Held? | Where the gap lives |
|---|---|---|---|
| D1 | A task can only be mutated by a project member with edit role | ✗ | [A1 IDOR](IDOR_AND_HASH_LEAK_AUDIT.md) — handler-level |
| D2 | A task's `assigneeId`, if non-null, references a member of the task's project | ✗ | [B1 Mass-assignment](MASS_ASSIGNMENT_AUDIT.md) — handler + missing DB check |
| D3 | `users.email` is unique | ✗ | Schema — no `@unique` (also a security race; [SECURITY_FINDINGS §3](SECURITY_FINDINGS.md)) |
| D4 | `users.email` is unique **case-insensitively** | ✗ | Schema + Zod — no normalisation; survives any `@unique` fix unless paired with `citext` / `lower()` index |
| D5 | A task's `position` is unique within `(project_id, status)` | ✗ | Schema + handler — `findFirst { max } + create` races; A1 IDOR amplifies |
| D6 | `tasks.assignee_id` is cleared when the assignee leaves the project's membership | ✗ | Cascade behaviour — no trigger / no use case |
| D7 | A project's `ownerId` is a member of the project with role `admin` | Partially (at create only) | Application logic — no DB constraint, drifts on any future role change |
| D8 | Every project has at least one admin | ✗ (no role-mgmt endpoint today, but no rule when added) | No constraint anywhere |
| D9 | `created_by_id` on a task is immutable | Yes by accident (Zod schema doesn't include it) | Application — no DB constraint, no audit log |
| D10 | `updated_at` reflects *meaningful* changes, not no-op writes | ✗ | No-op PATCH bumps `updatedAt` |
| D11 | Concurrent PATCHes don't silently lose either party's changes | ✗ | No optimistic concurrency control |
| D12 | Title, description, name are non-blank after trimming | ✗ | Zod allows whitespace-only strings |
| D13 | `description` has a single canonical "absent" value (null, not empty string, not undefined) | ✗ | Zod accepts all three forms; no normalisation in handler |
| D14 | An email/password is normalised consistently between register and login (case, trim) | ✗ | Login `findFirst({ where: { email } })` is case-sensitive against case-preserved storage |
| D15 | `position` is bounded — e.g. fits the column ordering, no overflow | ✗ | `z.number().int().min(0)` with no max |
| D16 | Every mutation has an audit record (who, what, when, before/after) | ✗ | No audit log table, no logger |
| D17 | Cascade deletes leave no semantically dangling references | Partially | Task.createdBy is `Restrict` (good); Task.assignee is `SetNull` (good); Project owner is `Restrict` (good); **Membership delete leaves orphan assignees** (D6) |
| D18 | The Airtable mirror stays in sync with Postgres | N/A today (mock only) | No retry queue, no reconciliation job, no idempotency key beyond `task.id` |
| D19 | Status transitions follow business rules (e.g., "review" requires reviewer) | ✗ | No state machine; any → any allowed |
| D20 | Tokens minted in environment A cannot operate on environment B | ✗ | No `aud` claim — see [SECURITY_FINDINGS §5](SECURITY_FINDINGS.md) |

---

## 3. New findings (not yet covered by other reports)

### D4 — Email uniqueness is case-sensitive only

**Where:** [prisma/schema.prisma:25](../prisma/schema.prisma#L25) (no `@unique` today; once added, will be case-sensitive in Postgres by default) + [src/schemas/auth.ts:4,10](../src/schemas/auth.ts#L4) (no `.toLowerCase()` / `.trim()`).

**The invariant that should hold:** A user is uniquely identified by the *semantic* email address. `meera@taskboard.dev` and `Meera@taskboard.dev` and `MEERA@TASKBOARD.DEV` must refer to the same account.

**Current behaviour:**
- Register stores the email verbatim.
- Login does `prisma.user.findFirst({ where: { email } })` — Postgres string equality is case-sensitive.
- An attacker registers `Meera@taskboard.dev`. The legitimate `meera@taskboard.dev` row already exists. The unique pre-check (`findFirst`) is case-sensitive too → both rows can coexist even after `@unique` is added.
- The legitimate user goes to log in with `meera@taskboard.dev` — finds their row. The attacker logs in with `Meera@taskboard.dev` — finds their own. Two accounts, same human, different passwords. Email becomes a useless identifier.

**Fix:**
1. Normalise at the boundary: Zod schemas should `.trim().toLowerCase()` the email.
2. Enforce in DB: add a unique index on `lower(email)` (Postgres allows expression indexes), or change the column type to `citext`.

```prisma
// schema.prisma
model User {
  ...
  email String @unique   // NOT case-insensitive by itself
  ...
}
```
…paired with a Prisma `migrate --create-only` and a hand-edit:
```sql
CREATE UNIQUE INDEX users_email_lower_unique ON users (LOWER(email));
```

```ts
// src/schemas/auth.ts
export const registerSchema = z.object({
  email: z.string().email().trim().toLowerCase(),
  ...
});
```

### D5 — `position` is not unique within `(project_id, status)`

**Where:** [prisma/schema.prisma:77](../prisma/schema.prisma#L77) — `position Int @default(0)` with no per-status uniqueness; [src/app/api/projects/[id]/tasks/route.ts:67-86](../src/app/api/projects/[id]/tasks/route.ts#L67-L86) — read-then-write without a transaction.

**The invariant:** Within a Kanban column (a `(project_id, status)` pair), no two tasks share the same `position`. Otherwise sort order is undefined.

**Current behaviour, two paths to break it:**

1. **Concurrent task creation race** (same shape as the register TOCTOU):
   - Two requests POST a task into "todo" of the same project at the same time.
   - Both `findFirst({ orderBy: { position: "desc" }})` return `position = 5`.
   - Both `create` with `position = 6`.
   - Now two tasks have `position = 6` in the same column.

2. **A1 IDOR + arbitrary position write**: any authenticated user can `PATCH /api/tasks/:id` with `{ "position": 0 }` for any task. Set ten tasks to `position = 0` and the column's sort becomes unstable.

**Fix:**

1. Add a partial-unique-or-defer constraint (Postgres-only):
   ```sql
   ALTER TABLE tasks
     ADD CONSTRAINT tasks_position_unique
     UNIQUE (project_id, status, position)
     DEFERRABLE INITIALLY DEFERRED;
   ```
   `DEFERRABLE` is essential — when dragging a task between two others, you transiently need duplicate positions until commit.

2. Switch to **fractional indexing** (`position FLOAT8` or `lexorank` strings). Inserting between `5.0` and `6.0` is `5.5`; between `5.5` and `6.0` is `5.75`. No need to rewrite siblings, no concurrency cliff. Best long-term fix; pairs with [PERFORMANCE_FINDINGS P15](PERFORMANCE_FINDINGS.md).

### D6 — Membership deletion leaves orphan assignees

**Where:** schema relations on `Task.assignee` (no application code triggers this, but the constraint isn't there).

**The invariant:** If user U is removed from project P's `memberships`, then no task in P has `assignee_id = U.id` afterwards.

**Today:** There is no endpoint to manage memberships, so this is latent. As soon as a future "remove member" endpoint ships, every task that user was assigned to remains assigned to them — the same illegal state that [B1](MASS_ASSIGNMENT_AUDIT.md) creates from the other direction.

**Fix:**

- DB-level: a trigger on `DELETE FROM memberships` that nulls out matching `tasks.assignee_id` for the same `project_id`.
- Application-level: any future "remove member" use case must clear assignments as part of the same transaction.
- Database CHECK: pair with the constraint suggested for D2 in [MASS_ASSIGNMENT_AUDIT.md §8.3](MASS_ASSIGNMENT_AUDIT.md) — a `CHECK` that any non-null `assignee_id` corresponds to an existing membership for the same project. Postgres can't natively express this as a CHECK (no subqueries) — it has to be enforced via trigger or via the DB-as-events model (write through a use case only).

### D7 / D8 — Owner / admin invariants

**Where:** [prisma/schema.prisma:43](../prisma/schema.prisma#L43) — `Project.ownerId` is a free-standing FK with no relationship to the `memberships` table. [src/app/api/projects/route.ts:54-57](../src/app/api/projects/route.ts#L54-L57) — at create, the owner is also given an admin membership. But the *relationship* between owner and membership is enforced only at this single point in code.

**The invariants:**
- **D7** — `project.ownerId` must equal *some* `memberships.user_id` for the same project, with `role = "admin"`.
- **D8** — Every project has ≥ 1 admin membership.

**Where they break:**
- A future "transfer ownership" feature that updates `Project.ownerId` without checking memberships → split-brain.
- A future "leave project" feature that deletes the owner's membership → project has an `ownerId` who isn't a member.
- A future "demote admin" feature → could leave a project with zero admins.

**Fix:**

- At the application layer: any use case that mutates membership/ownership must check these invariants in the same transaction.
- At the DB layer (defensive):
  ```sql
  ALTER TABLE projects
    ADD CONSTRAINT projects_owner_is_admin_member CHECK (
      EXISTS (SELECT 1 FROM memberships m
              WHERE m.project_id = projects.id
                AND m.user_id = projects.owner_id
                AND m.role = 'admin')
    ) NOT VALID;
  ```
  (Postgres doesn't allow subqueries in CHECK; use a trigger or move the rule into the use case. The CHECK syntax above is illustrative.)

### D10 — `updatedAt` is incremented on no-op PATCHes

**Where:** [src/app/api/tasks/[id]/route.ts:29-31](../src/app/api/tasks/[id]/route.ts#L29-L31) — `prisma.task.update({ data: parsed.data, …})` runs even when `parsed.data` equals the current values. Prisma's `@updatedAt` bumps regardless.

**The invariant:** `updated_at` reflects when the row's *content* last changed.

**Why it matters:**
- Combined with the [A1 IDOR](IDOR_AND_HASH_LEAK_AUDIT.md), an attacker can spam empty PATCHes to make every row look "recently active" — useful for laundering an exfil into normal-looking activity if any audit ever ships.
- `updatedAt` is sorted by clients to surface "recently changed" tasks → easily polluted.

**Fix:**
- In the use case, compare incoming patch against current state and skip `prisma.task.update` if nothing changed.
- Or: track a `version` integer (D11 fix below) and only bump on actual content delta.

### D11 — No optimistic concurrency control on PATCH

**Where:** every `PATCH` handler does `findUnique` → modify → `update` with no version check.

**The invariant:** Two clients editing the same task concurrently must either succeed in a defined order or one must be rejected — never silently lose the loser's changes.

**Today:** Last write wins. Bob and Alice both edit task "Draft press release" in their respective tabs at the same time:
1. Bob loads → version A.
2. Alice loads → version A.
3. Bob sets title → "Draft v2" → save → DB now version B with Bob's title.
4. Alice sets status → "done" → save → DB now version C with **Bob's title overwritten back to whatever Alice had loaded** + Alice's status change.

Bob's title change is silently lost.

**Fix — add a `version` column with check-and-set semantics:**

```prisma
model Task {
  ...
  version Int @default(0)
}
```

Client reads `version`, sends it back in the PATCH body, server runs:

```ts
const updated = await prisma.task.updateMany({
  where: { id, version: clientVersion },
  data: { ...parsed.data, version: clientVersion + 1 },
});
if (updated.count === 0) return conflict("task changed; please reload");
```

`updateMany` + a `WHERE version = ?` is atomic at the SQL layer. If two writers race, only one's `WHERE` matches; the other gets count = 0 and a 409.

Alternative: ETag + `If-Match` header. Same idea, HTTP-flavoured.

### D12 / D13 — Trimming and tristate normalisation

**Where:** [src/schemas/](../src/schemas/). None of the schemas call `.trim()`. `description` allows three "absent" values: `null`, `undefined`, and `""`.

**The invariants:**
- **D12** — A user-visible string field has visible content (≥ 1 non-whitespace character).
- **D13** — `description` has a single canonical "absent" representation.

**Why it matters:**
- Tasks can be created with title `"   "` (three spaces) → invisible in the UI, but exists.
- Search (`q=...`) and sort behave inconsistently on whitespace-only titles.
- A PATCH with `description: ""` versus `description: null` versus omitting `description` may result in three different stored states.

**Fix:**
```ts
title: z.string().trim().min(1).max(200);
description: z.string().trim().max(5000).transform(s => s === "" ? null : s).nullable().optional();
```
Combined with a DB-level CHECK on title (`length(trim(title)) > 0`) for defence in depth.

### D14 — Email normalisation drift between register and login

**Where:** Both [register](../src/app/api/auth/register/route.ts) and [login](../src/app/api/auth/login/route.ts) take email verbatim. No `.toLowerCase()` or `.trim()`.

**The invariant:** The address used at login normalises to the same key the account was registered under.

**Today:** Register as `meera@taskboard.dev` → login with `meera@taskboard.dev ` (trailing space) fails silently. Login with `Meera@taskboard.dev` fails (D4). Login with `\tmeera@taskboard.dev` fails. Pure UX foot-gun, but also a fingerprint of which address is registered (different error timing).

**Fix:** Same as D4 — normalise at the Zod boundary.

### D15 — `position` is unbounded

**Where:** [src/schemas/task.ts:18](../src/schemas/task.ts#L18) — `z.number().int().min(0).optional()`. No `max`.

**The invariant:** `position` fits the column ordering's expected range. (Subjective — depends on chosen scheme.)

**Today:** Attacker sets `position = 9_999_999_999` on any task via A1 → that column's sort is now bizarre. A signed-int overflow in a future re-balancing job is plausible.

**Fix:** Add `.max(1_000_000)` (or whatever the chosen position scheme permits). Or, after switching to fractional indexing, use a `Float` range like `(0, 2^53)`.

### D16 — No audit log

**Where:** Nothing. There is no `audit_logs` table, no logger calls in PATCH/DELETE handlers, no append-only log of mutations.

**The invariant:** Every mutation has a durable record of *who, what, when, before, after*.

**Why it matters:**
- After A1/B1 exploitation, the response is "we don't know who did it, when, or what they changed" — exactly the testimony the [IDOR PoC](IDOR_AND_HASH_LEAK_AUDIT.md) and [B1 PoC](MASS_ASSIGNMENT_AUDIT.md) demonstrated leaves no trace.
- Compliance: if this is ever B2B/enterprise, audit logs are non-negotiable.

**Fix:** Append-only table:
```prisma
model AuditLog {
  id         String   @id @default(cuid())
  actorId    String?
  action     String   // "task.update", "project.delete", etc.
  resourceId String
  before     Json?
  after      Json?
  ip         String?
  createdAt  DateTime @default(now())

  @@index([resourceId, createdAt])
  @@index([actorId, createdAt])
}
```
Wrap every use case (per [ARCHITECTURE_FINDINGS.md §4](ARCHITECTURE_FINDINGS.md)) in a `withAudit` decorator that records the operation. Once the application layer exists, this is one place.

### D17 — Cascade behaviour audit

**Today's behaviour (from schema inspection):**

| Delete | Effect |
|---|---|
| `User` who created a task | Blocked — `Task.createdBy` defaults to Restrict |
| `User` who owns a project | Blocked — `Project.owner` defaults to Restrict |
| `User` who is an assignee | Allowed — `Task.assignee` defaults to SetNull |
| `User` with memberships only | Allowed — `Membership.user` is Cascade |
| `Project` | Allowed — cascades into `Task` and `Membership` |
| `Membership` | **Leaves orphan `assignee_id`s on tasks** (D6) |

The Restricts are sensible safety nets. D6 is the only outright bug; the rest are reasonable for now but should be revisited if the product gains soft-delete semantics.

### D18 — Airtable sync has no consistency model

**Where:** [src/lib/airtable-mock.ts](../src/lib/airtable-mock.ts). The mock has a `failureRate` knob, but no application code uses it; whoever wires the real integration will need to design retries, idempotency, and reconciliation from scratch.

**The invariant (when implemented):** For every task in Postgres, there is exactly one corresponding Airtable record. The two diverge only during in-flight retries.

**Failure modes to design against:**
- Prisma write commits → Airtable call fails → divergence.
- Airtable call retries the same `task.id` after a successful commit — must be idempotent (mock's `id` parameter supports this, real impl must use it).
- Application crashes between Prisma commit and Airtable call — needs an outbox.
- Application restart with backlog of un-synced rows — needs a reconciler.

**Fix (when building the real impl):**
- **Transactional outbox**: write to a local `outbox` table in the same Prisma transaction; a worker drains the outbox to Airtable with idempotency.
- **Reconciliation job**: nightly compare `tasks` to Airtable, surface divergence.
- **Idempotency key**: `task.id` (the mock already supports this via the `id` parameter).

### D19 — No status transition rules

**Where:** [src/schemas/task.ts:13-19](../src/schemas/task.ts#L13-L19) — `status` is any `TaskStatus`. No state-machine.

**The invariant (potential):** Some products want `todo → in_progress → review → done` only, with no backwards moves except `review → in_progress`. Today: any → any is allowed.

If product semantics require it, encode the FSM in the domain Task entity (per [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md)) and reject illegal transitions in the use case. If they don't require it: leave alone; just document the choice so a future contributor doesn't assume otherwise.

### D20 — Cross-environment token replay

Covered in [SECURITY_FINDINGS §5](SECURITY_FINDINGS.md). Listed here because it's also an integrity issue: without an `aud` claim verified at the boundary, a token minted in one environment is structurally indistinguishable from one minted in another. Any future shared-secret slip (intentional or accidental) becomes a cross-environment data-mutation path.

---

## 4. Compounding effect with the existing IDOR + architecture findings

The user's intuition is right: the IDOR + lack of clean boundaries means **the surface that can corrupt the database is much wider than it looks**. Concretely, after A1 IDOR is applied to D5/D10/D11/D15:

- **A1 + D5**: an attacker sets `position = 0` on every task in a target project → that project's Kanban board becomes unsorted.
- **A1 + D10**: an attacker sends N no-op PATCHes on a project's tasks → all rows show recent `updatedAt`, polluting any "last edited" UI.
- **A1 + D11**: an attacker overwrites a task while a legitimate user is editing it → legitimate user's edits are silently lost; no conflict surfaced.
- **A1 + D2 + D15**: an attacker reassigns a task to a non-member with a wild `position` value → row is in an illegal state from two axes simultaneously.
- **A1 + D16 (no audit)**: every one of the above leaves no trace.

The first three are *exploitable today* — the IDOR is live, the integrity gaps are live, no theory required.

---

## 5. Why this happens — root causes shared with the other reports

Almost every D-finding maps back to the architectural gaps documented in [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md):

| Root cause | Findings it produces |
|---|---|
| No domain entities → invariants only live in the routes that happen to know about them | D1, D2, D7, D8, D9, D19 |
| No application layer → write paths are sprinkled; "every write goes through here" is not a thing | D5, D10, D11, D16 |
| Schema doesn't encode constraints → relying on application checks that may regress | D3, D4, D6, D7, D8, D14 |
| Zod schemas accept what the row column accepts; no normalisation step | D12, D13, D14, D15 |
| No port/adapter for external systems | D18 (Airtable consistency) |
| No transactional/audit boundary | D10, D11, D16 |

This is the same observation as the architecture report, applied to a different vertical axis. The fix is the same: introduce the use-case layer ([ARCHITECTURE_FINDINGS.md §4](ARCHITECTURE_FINDINGS.md)), encode invariants in entities, encode the rest in DB constraints / triggers as defence in depth.

---

## 6. Remediation order

This list interleaves with the security and performance fix orders — many are the *same* fix from a different angle.

### Tier 1 — Stop the bleeding (closes live integrity breaches)

1. **Patch [A1 + B1](MASS_ASSIGNMENT_AUDIT.md)** — closes D1, D2. (Already detailed.)
2. **Add `@unique` on `users.email`** with normalised input — closes D3, D4, D14 in one move.
3. **Add optimistic concurrency** (D11) — adds a `version` column, switch PATCH handlers to `updateMany` with version filter, return 409 on conflict.
4. **Trim + normalise text fields** (D12, D13, D14, D15) — at the Zod boundary, plus DB CHECKs for defence in depth.

### Tier 2 — Encode invariants in DB constraints

5. **Defer-unique on `(project_id, status, position)`** (D5) — or commit to fractional indexing (P15).
6. **Trigger to null assignees when memberships are deleted** (D6).
7. **Trigger or use-case-only path to keep `project.ownerId` consistent with admin membership** (D7, D8).
8. **Audit-log table + use-case decorator** (D16).

### Tier 3 — System design

9. **Status-machine in domain Task** (D19) — only if product semantics require.
10. **Airtable consistency design** (D18) — outbox + idempotency + reconciler, when the real implementation lands.
11. **`aud`/`iss` claims on JWTs** (D20) — bundled with [SECURITY_FINDINGS §5](SECURITY_FINDINGS.md).

---

## 7. What this codebase enforces correctly today (for balance)

Not everything is missing. The following are correctly modelled:

- **`@@unique([userId, projectId])` on Membership** — a user can have at most one membership per project.
- **Cascade-delete from Project → Membership and Task** — no orphan tasks/memberships after a project goes.
- **`Restrict` on `Project.owner` and `Task.createdBy`** — can't accidentally delete a user who still owns historical state.
- **`SetNull` on `Task.assignee`** — assignee cleared if the user is deleted; task survives.
- **Zod input validation runs on every mutating route** — the *shape* of input is sound, even if many *semantic* constraints are missing.
- **`select` discipline in `getCurrentUser`** ([lib/auth.ts:21](../src/lib/auth.ts#L21)) — the right pattern exists in the codebase; it just isn't applied everywhere yet (see [A2](IDOR_AND_HASH_LEAK_AUDIT.md)).
- **Composite index `(projectId, status)`** — supports the board fetch without extra joins.

---

## 8. Cross-references

- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) — security findings; D1, D2, D3/D4 (race), D20 (JWT) are the same items from a different angle.
- [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md) — many integrity fixes piggyback on performance fixes (e.g., D5 + P15 = fractional positions).
- [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md) — every D-finding maps to a missing architectural seam.
- [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md), [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md), [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md), [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md) — concrete PoCs that demonstrate the integrity breaches in §2.
