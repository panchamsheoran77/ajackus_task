# Architecture Improvement Analysis

**Project:** taskboard
**Date:** 2026-05-13
**Scope:** layering, boundaries, dependency flow, and modularity across [src/](../src/) — independent of (but cross-referencing) the security and performance audits.
**Verdict:** the codebase is currently a **flat Next.js scaffold** with no separation between HTTP, application, domain, and infrastructure concerns. Route handlers do everything inline. This is fine at the assessment's seeded scale but is the root cause of multiple security and performance issues already documented, and will dominate every future change unless a seam is introduced.

---

## 1. Executive summary

There are **no application, domain, or infrastructure boundaries**. The code lives in three places:

1. `src/app/api/.../route.ts` — Next.js HTTP entry points that _also_ perform input validation, authentication, authorization, business rules, persistence, and response shaping.
2. `src/lib/*.ts` — utility helpers (`prisma`, `jwt`, `auth`, `api-client`) that **mix HTTP concerns with domain concerns with infrastructure** (e.g., `auth.ts` returns `NextResponse` directly).
3. `src/components/*`, `src/app/<page>/page.tsx` — React UI.

The consequences are already concrete and measurable in the audit reports:

| Symptom                                                                                                               | Caused by missing boundary                                        |
| --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 7+ files import `prisma` directly                                                                                     | No repository abstraction                                         |
| Authorization checks duplicated inline in every route (and inconsistent — see [A1 IDOR](IDOR_AND_HASH_LEAK_AUDIT.md)) | No policy/use-case layer                                          |
| `passwordHash` accidentally crosses the wire ([A2](IDOR_AND_HASH_LEAK_AUDIT.md))                                      | DTO/domain conflation in [src/types/index.ts](../src/types/index.ts) |
| Same `getCurrentUser → getProjectMembership → query` waterfall everywhere (W1)                                        | No use-case orchestration to dedupe                               |
| Adding rate-limiting / audit log / tracing would require editing every route                                          | No cross-cutting decorator point                                  |
| Mocking the DB for tests is hard                                                                                      | No dependency-injection seam                                      |
| Three independent shape definitions of `Task`: Prisma schema, Zod schema, TS type                                     | No single source of truth                                         |

This report proposes a minimal **Clean Architecture / Hexagonal-style layering** sized for this project — not enterprise overkill, but enough to add the missing seams.

---

## 2. Current architecture (as-is)

### 2.1 File layout

```
src/
├── app/
│   ├── api/                          ← HTTP entry points, but ALSO do everything
│   │   ├── auth/
│   │   │   ├── login/route.ts        ← parses body, queries Prisma, hashes,
│   │   │   ├── register/route.ts       signs JWT, formats response — all inline
│   │   ├── projects/
│   │   │   ├── route.ts              ← list + create (auth + persistence + mapping)
│   │   │   └── [id]/
│   │   │       ├── route.ts          ← GET/PATCH/DELETE all in one file
│   │   │       └── tasks/route.ts    ← inline SQL injection lives here
│   │   ├── tasks/[id]/route.ts       ← inline IDOR lives here
│   │   └── users/me/route.ts
│   ├── login/page.tsx                ← React + fetch
│   ├── register/page.tsx
│   ├── dashboard/page.tsx
│   ├── projects/[id]/page.tsx
│   └── layout.tsx
├── components/                       ← React only, fine
├── lib/                              ← mixed-concern utilities
│   ├── prisma.ts                     ← infrastructure
│   ├── jwt.ts                        ← infrastructure (crypto adapter)
│   ├── auth.ts                       ← MIXED: domain rules + HTTP responses + Prisma
│   ├── api-client.ts                 ← client-side helper (different concern)
│   └── airtable-mock.ts              ← test double with no production counterpart
├── schemas/                          ← Zod input validators only
├── types/index.ts                    ← shared TS types — but used for both API and domain
└── tests/                            ← tests pinned to lib/* and components/*
```

### 2.2 Dependency graph (current)

```
       ┌─────────────────────────┐
       │   route.ts (HTTP)        │
       └────────┬────────────────┘
                │ imports directly
   ┌────────────┼─────────────┬─────────────┐
   ▼            ▼             ▼             ▼
 prisma      jwt          auth.ts        schemas (Zod)
   ▲                        │ ▲
   └────────────────────────┘ │
                              │
                       returns NextResponse
                       (HTTP leak into helpers)
```

Every layer talks to every other layer. There's no acyclic dependency direction. A change to the Prisma schema can ripple into route handlers, type files, and React components without any compile-time seam to alert you.

### 2.3 What lives where today (and why it's wrong)

| File                                   | Concerns it currently mixes                                                                                                                   |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/api/projects/[id]/route.ts`       | HTTP parsing · auth check · authorization rule · Prisma query (with security-relevant `include: true` — see A2) · response shaping            |
| `app/api/projects/[id]/tasks/route.ts` | Same — plus raw SQL string concatenation (SQLi root cause)                                                                                    |
| `app/api/tasks/[id]/route.ts`          | Same — plus inconsistent auth between PATCH and DELETE (root cause of A1)                                                                     |
| `lib/auth.ts`                          | Domain rule (`canEditTasks`) · infrastructure call (`prisma.membership.findUnique`) · HTTP response (`NextResponse.json({…}, {status: 401})`) |
| `types/index.ts`                       | API response DTOs · domain entity types · UI prop types (one type plays three roles, hence `passwordHash?: string` leaks across all of them)  |
| `schemas/task.ts`                      | Input validation (HTTP concern) · de-facto domain shape (because no other shape exists)                                                       |

---

## 3. Findings — what's missing and why each matters

### 3.1 No domain layer

**What:** No entities (rich types with invariants), no value objects (`Email`, `Role`, `TaskStatus`, `Position`), no domain services, no domain errors. The closest thing is Prisma's auto-generated types, which are _persistence shapes_, not domain models.

**Pain it causes today:**

- Business rules expressed as throwaway booleans in `lib/auth.ts` (`canEditTasks`, `canEditProject`) rather than entity methods.
- Validity invariants live in the database (`@@unique`, FK constraints) and in Zod (input shape), but **nothing enforces them in code** — e.g., the [B1 cross-project-assignee bug](MASS_ASSIGNMENT_AUDIT.md) is a missing invariant: "an assignee must be a member of the task's project". A domain `Task` entity would never accept an `assigneeId` without that check, by construction.

### 3.2 No application layer (use cases)

**What:** Every business operation — "list a user's projects", "create a task", "reassign a task" — is implemented as a Next.js `route.ts` handler. There's no `createTask(input, ctx)` function that can be called from anywhere else.

**Pain it causes today:**

- The same auth-then-membership-then-query [waterfall (W1)](PERFORMANCE_FINDINGS.md) is repeated in 7+ files.
- Cross-cutting concerns (audit log, tracing, retries, rate-limits, caching, transactions) have no single point of attachment — they have to be added inline to every route.
- The same business logic can't be exposed through a future CLI, background job, or GraphQL route without copy-paste.

### 3.3 No infrastructure boundary — Prisma is everywhere

**What:** `prisma` is a transitive dependency of every route handler. There's no `TaskRepository`, no `UserRepository`. Swapping Postgres for SQLite (or adding a read-replica, or a query cache, or Prisma Accelerate) means editing every route.

**Pain it causes today:**

- Adding the LRU cache from [PERFORMANCE_FINDINGS C2](PERFORMANCE_FINDINGS.md) requires either monkey-patching Prisma or adding cache reads inside every route.
- Tests cannot substitute a fake DB. The current tests at `src/tests/` only cover pure functions (`schemas`, the JWT-less parts of `auth.ts`); there's no use-case test because there's no use case to test.

### 3.4 No ports / adapters — the Airtable seam is missing one half

**What:** [src/lib/airtable-mock.ts](../src/lib/airtable-mock.ts) defines a _concrete_ test double, not an _interface_ (port). There's no `AirtableSyncPort` that the application depends on and that the mock and real impls both satisfy. The README and code comments imply a real integration is expected but the swap site is undefined.

**Pain it causes today:**

- Whoever wires the real Airtable integration has to decide where it lives and what it depends on — there's no contract to satisfy.
- The mock and real impls will inevitably drift unless they share a typed interface.

### 3.5 HTTP concerns leak into lower layers

**What:** [src/lib/auth.ts:26-40](../src/lib/auth.ts#L26-L40) defines `unauthorized()`, `forbidden()`, `badRequest()`, `notFound()` that return `NextResponse` directly. These are HTTP concerns living inside what should be a domain/auth helper.

**Pain it causes today:**

- The same auth checks can't be reused outside an HTTP context (e.g., from a future GraphQL resolver, a background job that needs to verify permissions, or a CLI admin command).
- Error mapping (`badRequest` vs `notFound` vs `forbidden`) is duplicated and inconsistent (e.g., the user-existence oracle in [B1](MASS_ASSIGNMENT_AUDIT.md) leaks 500 vs 200 — a domain layer would have raised a single typed error and the boundary would have mapped it cleanly).

### 3.6 DTO ↔ domain conflation in types

**What:** [src/types/index.ts](../src/types/index.ts) defines `ApiUser`, `ApiTask`, `ApiProjectDetail`, `ApiProjectMember` — all suffixed `Api*` suggesting they're HTTP DTOs — but used directly as component prop types AND as the de-facto domain model. `ApiUser` declares `passwordHash?: string` because the API response actually leaks it ([A2](IDOR_AND_HASH_LEAK_AUDIT.md)) and the type was widened to match reality.

**Pain it causes today:**

- The optional `passwordHash` field shows that types were _retrofitted_ to the leaky reality, instead of types defining what _should_ be on the wire.
- Three separate shape definitions (Prisma → Zod → `ApiUser`) with no single source of truth. Drift is inevitable.
- No place to add field-level transformations (e.g., `createdAt: Date` in domain, `createdAt: string` in API). Today everything is string because that's what JSON gives you.

### 3.7 No configuration boundary

**What:** Env vars are read directly in the modules that need them: `JWT_SECRET` in `lib/jwt.ts`, `DATABASE_URL` consumed by Prisma's generator config. There's no central `config.ts` that loads and validates env at startup.

**Pain it causes today:**

- No record of what env vars the app _needs_ — drift between `.env.example`, `docker-compose.yml`, and actual code is unenforced; a missing or mistyped key surfaces as a runtime error in whichever route happens to read it first, rather than at boot.
- No single place to add format / strength validation (e.g., "`JWT_SECRET` must be ≥32 bytes high-entropy", "`DATABASE_URL` must be a valid Postgres URL"). A Zod-validated config module would refuse to start with unset or trivially weak values.

### 3.8 No dependency injection / composition root

**What:** All dependencies are resolved via static imports at file load time. There's no `composition root` where `prisma`, `jwt`, `hasher`, `airtable` are wired up.

**Pain it causes today:**

- Test mocking requires module-level mocking (e.g., `vi.mock("../lib/prisma")`), which is brittle.
- A multi-tenant deployment that needed per-tenant Prisma clients would need re-architecting.

### 3.9 No middleware for cross-cutting concerns

**What:** [src/middleware.ts](../src/middleware.ts) does not exist. Auth is re-implemented in every route via `getCurrentUser`. There's no place to attach rate limiting, request logging, tracing, CORS policy, security headers, or request-id propagation.

**Pain it causes today:**

- Every security finding that needed rate limiting ([SECURITY_FINDINGS §4](SECURITY_FINDINGS.md)) and every header gap ([XSS_TOKEN_AUDIT §2](XSS_TOKEN_AUDIT.md) — no CSP, X-Frame, etc.) has no natural place to be fixed once for the whole app.

### 3.10 No clear delivery-mechanism boundary

**What:** The web UI and the API are co-mingled inside `app/`. Today both are Next.js, but the React pages directly call the API via `apiFetch`, which assumes same-origin and bearer-token-in-header.

**Pain it causes today:**

- The auth/token storage is wired to a localStorage + Bearer-header model that the security audit ([XSS_TOKEN_AUDIT](XSS_TOKEN_AUDIT.md)) recommends moving away from. With a clean delivery boundary, the auth mechanism would be swappable per-delivery (httpOnly cookie for web, bearer for mobile/CLI).

---

## 4. Proposed target architecture

This is intentionally **minimal** for this project's scale — not enterprise-DDD overkill. The goal is exactly four layers, each with a single direction of dependency.

### 4.1 Layered folder structure

```
src/
├── domain/                         ─── no I/O, no framework imports
│   ├── entities/
│   │   ├── user.ts                 ─── User entity + invariants
│   │   ├── project.ts
│   │   ├── task.ts                 ─── e.g. Task.reassign(newAssignee, membership) — enforces B1 invariant
│   │   └── membership.ts
│   ├── value-objects/
│   │   ├── email.ts                ─── validated Email
│   │   ├── role.ts                 ─── "admin" | "member" | "viewer" with predicates
│   │   ├── task-status.ts
│   │   └── position.ts             ─── fractional indexing if adopted
│   ├── policies/                   ─── reusable rules
│   │   ├── can-edit-task.ts
│   │   └── can-edit-project.ts
│   └── errors/                     ─── typed domain errors
│       ├── not-a-member.ts
│       ├── viewer-cannot-edit.ts
│       ├── email-already-registered.ts
│       └── assignee-not-in-project.ts
│
├── application/                    ─── orchestrates the domain via ports
│   ├── ports/                      ─── interfaces the infrastructure implements
│   │   ├── user-repository.ts
│   │   ├── project-repository.ts
│   │   ├── task-repository.ts
│   │   ├── membership-repository.ts
│   │   ├── password-hasher.ts
│   │   ├── token-signer.ts
│   │   ├── airtable-sync.ts        ─── port for the Airtable integration
│   │   ├── clock.ts                ─── for testable timestamps
│   │   └── logger.ts
│   └── use-cases/
│       ├── auth/
│       │   ├── login.ts
│       │   └── register.ts
│       ├── project/
│       │   ├── list-projects-for-user.ts
│       │   ├── create-project.ts
│       │   ├── update-project.ts
│       │   ├── delete-project.ts
│       │   └── get-project-detail.ts
│       └── task/
│           ├── create-task.ts
│           ├── update-task.ts      ─── A1 + B1 invariants enforced at this layer
│           ├── delete-task.ts
│           └── list-tasks.ts
│
├── infrastructure/                 ─── concrete adapters
│   ├── persistence/
│   │   ├── prisma/
│   │   │   ├── client.ts           ─── (today's lib/prisma.ts)
│   │   │   ├── user-repository.ts  ─── implements UserRepository
│   │   │   ├── project-repository.ts
│   │   │   ├── task-repository.ts
│   │   │   └── membership-repository.ts
│   │   └── cached/                  ─── decorators wrapping the prisma impls (LRU, singleflight)
│   ├── crypto/
│   │   ├── bcrypt-hasher.ts
│   │   └── jsonwebtoken-signer.ts
│   ├── external/
│   │   ├── airtable-client.ts      ─── REAL Airtable implementation
│   │   └── airtable-mock.ts        ─── current mock, moved here
│   ├── config/
│   │   └── env.ts                  ─── Zod-validated env at startup
│   └── logging/
│       └── pino-logger.ts          ─── (or whatever)
│
└── interfaces/                     ─── delivery mechanisms (currently only Next.js)
    ├── http/
    │   ├── middleware.ts           ─── auth, rate-limit, request-id, security headers
    │   ├── compose.ts              ─── composition root: wires ports → adapters
    │   ├── error-mapper.ts         ─── domain error → HTTP status
    │   ├── api/                    ─── (today's app/api/, but thin)
    │   │   ├── auth/login/route.ts ─── 5-10 lines: parse → call login() → map result
    │   │   └── …                   ─── one file per current route, each tiny
    │   └── schemas/                ─── (today's src/schemas/ — HTTP input Zod schemas)
    └── web/                        ─── (today's app/<page>/page.tsx and components/)
        ├── pages/                  ─── Next.js pages
        ├── components/
        └── api-client.ts           ─── (today's lib/api-client.ts)
```

### 4.2 Dependency direction (must be acyclic)

```
        interfaces/ ───┐
                       │
              ┌────────▼────────┐
              │ application/    │
              │  (use cases)    │
              └────────┬────────┘
                       │ depends on
                       ▼
              ┌─────────────────┐
              │    domain/       │
              │  (pure logic)    │
              └─────────────────┘
                       ▲
                       │ implements
              ┌────────┴────────┐
              │ infrastructure/ │
              └─────────────────┘
```

- `domain/` depends on **nothing**. No Prisma, no Next.js, no `fetch`, no env.
- `application/` depends on `domain/` and on its own `ports/`. **Not** on infrastructure.
- `infrastructure/` depends on `application/ports/` (to implement them) and on `domain/` (to construct entities from rows). **Not** on `interfaces/`.
- `interfaces/` depends on `application/` (to call use cases) and on its own DTOs/schemas. Maps HTTP ↔ use-case input/output at the boundary.

A lint rule (`eslint-plugin-boundaries` or `eslint-plugin-import` with restricted-paths) can enforce this at CI time so the boundary doesn't degrade silently.

### 4.3 What a typical route becomes

Today, `app/api/tasks/[id]/route.ts` `PATCH` is ~25 lines of mixed concerns. After:

```ts
// src/interfaces/http/api/tasks/[id]/route.ts
import { compose } from "@/interfaces/http/compose";
import { updateTaskSchema } from "@/interfaces/http/schemas/task";
import { errorToResponse } from "@/interfaces/http/error-mapper";

export async function PATCH(req: NextRequest, { params }: Params) {
  const { id } = await params;
  const body = await req.json().catch(() => null);
  const parsed = updateTaskSchema.safeParse(body);
  if (!parsed.success)
    return errorToResponse({ kind: "bad-input", details: parsed.error });

  const ctx = await compose.requestContext(req); // pulls user from JWT
  if (!ctx.user) return errorToResponse({ kind: "unauthorized" });

  const result = await compose.useCases.task.updateTask({
    taskId: id,
    input: parsed.data,
    actor: ctx.user,
  });
  return result.match({
    ok: (task) => NextResponse.json({ task }),
    err: errorToResponse,
  });
}
```

The route handler is back to being a _delivery shim_ — parse, call the use case, map the result. The actual logic (load task, check caller's membership, check assignee's membership, apply the update, sync to Airtable) lives in `application/use-cases/task/update-task.ts`. The same use case can later be called from a GraphQL resolver, a CLI, a queue worker, without duplication.

### 4.4 Where the existing audit fixes land

This is the payoff. Each fix from the security and performance reports has a **single clear destination** in the target architecture:

| Existing finding                                      | New home                                                                                                                                                                                                                          |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [A1 IDOR on task PATCH](IDOR_AND_HASH_LEAK_AUDIT.md)  | `application/use-cases/task/update-task.ts` enforces "caller must be project member with edit role" via `Task.editBy(actor, membership)`                                                                                          |
| [A2 `passwordHash` leak](IDOR_AND_HASH_LEAK_AUDIT.md) | `domain/entities/user.ts` has no `passwordHash` getter; only `UserRepository.findCredentials()` returns it. HTTP DTOs in `interfaces/http/` cannot reference it                                                                   |
| [B1 cross-project assignee](MASS_ASSIGNMENT_AUDIT.md) | `Task.reassign(newAssignee, projectMembership)` raises `AssigneeNotInProjectError` at the domain layer                                                                                                                            |
| [SQLi in task search](SQL_INJECTION_AUDIT.md)         | `application/use-cases/task/list-tasks.ts` takes a typed `{ q?: string }` and calls `taskRepository.search()`. Repository implementations are responsible for safe parameterization — no raw SQL escapes the infrastructure layer |
| [Race on register](SECURITY_FINDINGS.md)              | `UserRepository.create` raises `EmailAlreadyRegisteredError` (mapped from P2002); use-case relies on the DB invariant, no pre-check                                                                                               |
| [Rate limiting](SECURITY_FINDINGS.md)                 | `interfaces/http/middleware.ts` — one place, applies everywhere                                                                                                                                                                   |
| [JWT claims](SECURITY_FINDINGS.md)                    | `infrastructure/crypto/jsonwebtoken-signer.ts` — only place that mints tokens                                                                                                                                                     |
| [W1 auth waterfall](PERFORMANCE_FINDINGS.md)          | `infrastructure/persistence/cached/user-repository.ts` decorates the Prisma impl with an LRU                                                                                                                                      |
| [P2 over-fetch](PERFORMANCE_FINDINGS.md)              | `infrastructure/persistence/prisma/project-repository.ts` controls the `select` shape; HTTP DTOs are projected separately                                                                                                         |
| [Airtable integration](../src/lib/airtable-mock.ts)      | `application/ports/airtable-sync.ts` defines the contract; mock and real impls live side-by-side in `infrastructure/external/`                                                                                                    |

Once the seams are in place, every future finding has an obvious destination too. Without the seams, every fix is a special case.

---

## 5. Migration plan (incremental, no big-bang rewrite)

Doing this all at once is risky. The recommended order opens the seam _first_, then drains code into it.

### Step 1 — Add the `interfaces/`, `application/`, `infrastructure/`, `domain/` folders empty

No code moves yet. Just establish the targets. Add an ESLint rule restricting cross-layer imports.

### Step 2 — Extract ports (interfaces only)

Define `UserRepository`, `ProjectRepository`, `TaskRepository`, `MembershipRepository`, `PasswordHasher`, `TokenSigner` as TS interfaces in `application/ports/`. **No bodies yet.**

### Step 3 — Implement the Prisma adapters

Move the contents of `lib/prisma.ts` into `infrastructure/persistence/prisma/client.ts`. Write `prisma/<entity>-repository.ts` files that implement each port using `prisma.user.findUnique(...)` etc. **Don't change route handlers yet.**

### Step 4 — One use case at a time

Pick a small use case (e.g., `getMe` for `GET /api/users/me`). Extract its logic into `application/use-cases/auth/get-me.ts`. The route handler becomes a thin shim. Verify nothing breaks. Then the next route. This is the bulk of the work but each step is small and reversible.

### Step 5 — Replace `lib/auth.ts`

Split into:

- `domain/policies/` — the predicate functions (`canEditTask`, `canEditProject`) — pure, no `NextResponse`.
- `interfaces/http/middleware.ts` — token-from-header extraction; sets `req.user` (typed).
- `interfaces/http/error-mapper.ts` — the `unauthorized()` / `forbidden()` / `badRequest()` / `notFound()` HTTP mapping.

### Step 6 — Split `types/index.ts`

- `domain/entities/*.ts` — domain types.
- `interfaces/http/schemas/*.ts` — Zod schemas (already exist; move here).
- `interfaces/http/dto/*.ts` — output DTOs, with explicit field projection (no `passwordHash`).
- `interfaces/web/view-models/*.ts` — UI view models (could equal DTOs initially).

### Step 7 — Composition root

Create `interfaces/http/compose.ts` that instantiates the adapters and assembles the use cases. Route handlers import `compose.useCases.task.updateTask` rather than wiring dependencies themselves. (One place to swap to cached / instrumented / mock variants.)

### Step 8 — Configuration boundary

Move every env-var read into `infrastructure/config/env.ts`, validated with Zod at module load. Other modules import `env.JWT_SECRET` etc., and the app refuses to start if any required key is missing or fails its strength check.

### Step 9 — Cross-cutting concerns

With the seams in place, add: structured logging in `infrastructure/logging/`, rate limiting in `interfaces/http/middleware.ts`, request-id propagation, audit logging via a use-case decorator, observability hooks.

### Step 10 — Lint-enforce the boundary

Turn on `eslint-plugin-boundaries` to ensure no future PR can `import "@/lib/prisma"` from a `domain/` file or `import "next/server"` from an `application/` file.

---

## 6. Trade-offs and what NOT to do

### 6.1 What to keep simple

- **No CQRS, no event sourcing, no domain events bus.** This is a CRUD board app; the conceptual overhead doesn't pay back at this scale.
- **No DDD aggregates with persistence-ignorant root entities.** Plain entities + repository pattern is enough.
- **No mediator pattern / MediatR-style request handlers.** Direct use-case functions are simpler and equally testable.
- **No interface for things with one implementation forever.** `Clock` and `Logger` are worth the indirection because tests substitute them; `PrismaClient` itself is not — the port is `UserRepository`, not "PrismaWrapper".
- **No service classes if functions suffice.** `createTask(input, deps): Promise<Result<Task, DomainError>>` is fine as a free function; only wrap in a class if you have shared state.

### 6.2 What this is _not_

- **Not microservices.** This is a single Next.js app with clean _internal_ boundaries. The deployment unit stays one. If a future service split is needed, the seams are exactly where you'd cut.
- **Not "purity for purity's sake."** Every boundary above is justified by an existing audit finding having a destination. No layer is added speculatively.
- **Not a Java-style enterprise design.** TypeScript expressiveness lets a lot of this be free functions, typed unions, and discriminated `Result` types — not `IFooFactoryFactory`.

### 6.3 When to abandon a piece of this

- If the team is 1-2 people and the codebase stays under ~10k LOC for the foreseeable future, the `domain/` layer can stay thin — value objects and entity invariants matter most; you can skip explicit domain services.
- If you never get a second delivery mechanism (CLI, GraphQL, mobile-direct), `interfaces/` collapsing back into `app/` is fine; the rest of the layering still earns its keep.

---

## 7. Concrete deltas the layering would have prevented

Re-reading the audit reports through the lens of architecture, these specific incidents trace back to a missing boundary:

| Audit finding                                                             | Architectural root cause                                                                                                                                                                                         |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [SQLi in task search](SQL_INJECTION_AUDIT.md)                             | Raw SQL written inside the HTTP handler. With a `TaskRepository.search(query: string)` port, only the infrastructure adapter could be the place this lives, and it would have to be reviewed in one focused file |
| [`passwordHash` leak in project detail](IDOR_AND_HASH_LEAK_AUDIT.md)      | Persistence shape used as API DTO. A domain `User` entity + a separate HTTP DTO with explicit field projection makes this impossible by construction                                                             |
| [IDOR on task PATCH](IDOR_AND_HASH_LEAK_AUDIT.md)                         | Authorization scattered. A single `application/use-cases/task/update-task.ts` would have the check in exactly one place — no `DELETE has it, PATCH doesn't` inconsistency                                        |
| [Mass assignment / cross-project assignee](MASS_ASSIGNMENT_AUDIT.md)      | Zod input passed straight to `prisma.task.update`. A use case constructs a domain `Task.reassign(newAssignee, callerMembership)` that refuses the operation if the assignee isn't a project member               |
| [Multiple-rounding-trips waterfalls](PERFORMANCE_FINDINGS.md) (W1–W7)     | Auth + membership + data fetch repeated in every route. A use case calls a single repository method that does the join in one query — one place to optimize                                                      |
| [No rate limit, no CSP, no audit log, no logging](SECURITY_FINDINGS.md)   | No middleware, no composition root. With `interfaces/http/middleware.ts` + a logger port, each lands in one place                                                                                                |
| [Airtable mock has no production peer](../src/lib/airtable-mock.ts)          | No port defined. Once `AirtableSync` is a named interface, both impls satisfy it and tests can swap freely                                                                                                       |

---

## 8. Recommendation summary

Open the seams **once**, then drain the code into them incrementally. The 10-step plan in §5 can ship in vertical slices — one route, one use case at a time — with no big-bang rewrite. At every intermediate state the app is still working.

The biggest leverage is in **steps 4 + 5 + 6** — extracting use cases, splitting `lib/auth.ts`, splitting `types/index.ts`. Those three changes give you:

- A single place per business operation (kills duplication and authorization drift).
- A domain/HTTP boundary (kills the `passwordHash` leak class of bug structurally).
- A point of attachment for every cross-cutting concern the audits flagged.

Steps 7-10 (composition root, config, middleware, lint enforcement) are smaller and can come later once the layering is established.

---

## 9. Cross-references

- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) — 10 security findings, most of which trace back to a missing architectural boundary (see §7).
- [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md) — 30 perf findings; the W1–W7 waterfalls disappear naturally once auth and data fetching are colocated in use cases.
- [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md), [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md), [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md), [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md), [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) — detailed PoCs the architecture refactor would prevent recurring.
