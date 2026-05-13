# Performance Findings — Final Consolidated Report

**Project:** taskboard
**Date:** 2026-05-13
**Scope:** Full-stack performance audit of [src/](../src/), [prisma/](../prisma/), [Dockerfile](../Dockerfile), and the React Query / data-fetching layer.
**Method:** static read-through of every API route, every client page, the Prisma schema, the Dockerfile, and `package.json`; cross-referenced against the security findings to flag fixes that improve both axes simultaneously.

**Honest scale caveat:** at the seeded scale (5 users / 3 projects / 12 tasks) **none of these are user-visible**. The endpoints all return in single-digit milliseconds. This list ranks issues by how they break as the dataset grows to "real" sizes — hundreds of tasks per project, dozens of projects per user, dozens of concurrent users. Each finding includes the scale at which it actually starts to hurt.

---

## 1. Summary table

| # | Finding | Category | Hurts at … | Effort |
|---|---|---|---|---|
| P1 | `taskCount` computed via `tasks: true` (fetches every task to call `.length`) | DB | 10 projects × 100+ tasks | Trivial |
| P2 | `GET /api/projects/:id` over-fetches + duplicates user rows per task | DB | 50+ tasks per project | Low |
| P3 | Missing indexes on `users.email`, `projects.ownerId`, `tasks.assigneeId`, `tasks.createdById` | DB | 10k+ users | Migration |
| P4 | `bcryptjs` (pure JS) blocks the event loop on login/register | CPU | Any concurrent auth burst | Trivial |
| P5 | Every task mutation `invalidateQueries(["project", id])` → full project refetch | Frontend | Multi-user boards | Medium |
| W1 | 3-step auth-then-data chain on every protected route | Waterfall | Every request, always | Low |
| W2 | `GET /api/projects/:id` is 3 RT, could be 1 | Waterfall | Every project page load | Low |
| W3 | `POST /api/projects/:id/tasks` is 4 RT, could be 1 | Waterfall | Burst task creation | Low |
| W4 | `PATCH /api/tasks/:id` becomes 5 RT after security fixes | Waterfall | Task editing | Low |
| W5 | `DELETE /api/tasks/:id` is 3 RT, could be 1 | Waterfall | Task deletion | Low |
| W6 | Register is `findFirst` + `create` — 2 RT (also a TOCTOU) | Waterfall | Concurrent signups | Schema migration |
| W7 | `getCurrentUser` does a DB lookup on every authenticated request | Waterfall | Every request | Medium |
| W8 | Login → dashboard cold start: two sequential network RTs | Waterfall | First navigation post-login | Low |
| W10 | Task save → invalidate → refetch (6 RT user-visible) | Waterfall | Every task save | Medium |
| C1 | No HTTP cache headers anywhere (`Cache-Control`, `ETag`, etc.) | Caching | Every refetch / SWR scenario | Low |
| C2 | No server-side cache (Redis / LRU / Next.js `unstable_cache`) | Caching | High-concurrency reads | Medium |
| C3 | No request-scoped memoization for `getCurrentUser` / `getProjectMembership` | Caching | Compound queries in one request | Low |
| C4 | TanStack `staleTime` is a single global value, no jitter | Caching | Synchronized cache-expiry storms | Trivial |
| C5 | Client cache not persisted — tab refresh = cold cache | Caching | Heavy navigation users | Medium |
| TH1 | Cache-expiry storm on `GET /api/projects` for many users at once | Herd | ~100 concurrent users near same `staleTime` | Bundled with C1+C4 |
| TH2 | Login storm — pure-JS bcrypt serializes on the main thread | Herd | Today, under any auth burst | Bundled with P4 |
| TH3 | Board invalidation fan-out: N viewers refetch on each task edit | Herd | Multi-user boards | Bundled with P5 |
| TH4 | `getCurrentUser` hit 100× when one user has 100 in-flight requests | Herd | High per-user concurrency | Bundled with W7 + C3 |
| TH5 | No `Promise.all` / coalescing pattern anywhere in the API | Herd | Multi-instance deployments | Medium (singleflight) |
| P11 | Default Prisma connection pool = `2*CPU + 1`, easy to exhaust | Infra | Single-vCPU containers under burst | Trivial |
| P12 | Dockerfile uses `npm install` instead of `npm ci` | Infra | Image build time / reproducibility | Trivial |
| P13 | Turbopack only in `next dev`, not `next build` | Infra | Build time | Optional |
| P14 | No explicit compression / Brotli config in `next.config.ts` | Infra | Large API responses | Low |
| P15 | Position-based task ordering rewrites N rows on middle inserts | Future | Drag-and-drop on 500+ task boards | Schema redesign |
| P16 | Re-renders not memoized (no `React.memo` on `TaskCard`) | Frontend | 200+ task boards | Trivial |
| P17 | `airtable` dep ships ~150 KB if accidentally imported into a client component | Frontend | First load of any page that imports it | Code-review check |
| W9 | No hover-prefetch on project links | Frontend (UX) | Dashboard → project navigation | Trivial |
| W11 | `Header` reads localStorage in `useEffect` → name flashes blank-then-filled | Frontend (UX) | Every page navigation | Low |

---

## 2. Detailed findings by category

### 2.1 Database / query patterns

#### P1 — N+1 over-fetch in dashboard project list
[src/app/api/projects/route.ts:10-31](../src/app/api/projects/route.ts#L10-L31). `include: { tasks: true }` pulls every task row across every project the user is on, then JavaScript does `m.project.tasks.length`. For 10 projects × 100 tasks = 1,000 rows hauled across the wire to compute 10 integers.
**Fix:** swap to `_count: { select: { tasks: true } }` — single aggregate in Postgres.

#### P2 — Massive over-fetch + duplicate user payload on project detail
[src/app/api/projects/[id]/route.ts:25-40](../src/app/api/projects/[id]/route.ts#L25-L40). `include: { owner: true, memberships: { include: { user: true } }, tasks: { include: { assignee: true, createdBy: true } } }` returns every User column (including `passwordHash` — same root cause as [IDOR_AND_HASH_LEAK_AUDIT.md A2](IDOR_AND_HASH_LEAK_AUDIT.md)). Same admin's User row may appear dozens of times in one response.
**Fix:** explicit `select` on every join; drop `createdBy` if the UI doesn't render it; paginate `tasks`.

#### P3 — Missing indexes on hot FK columns
[prisma/schema.prisma](../prisma/schema.prisma) has `@@index([projectId])` and `@@index([projectId, status])` (good), and the composite `@@unique([userId, projectId])`. Missing:

| Column | Used by |
|---|---|
| `users.email` | login `findFirst` ([api/auth/login/route.ts:16](../src/app/api/auth/login/route.ts#L16)) and register pre-check |
| `projects.ownerId` | "projects I own" + cascade analysis |
| `tasks.assigneeId` | "tasks assigned to me" |
| `tasks.createdById` | audit queries |

Today every login is a sequential scan of `users`. Trivial at 5 users, painful at 10k+. Add `email String @unique` (closes the [security race condition](SECURITY_FINDINGS.md) at the same time) and `@@index` for the three FK columns.

#### P6 — Two round trips on every task create
[src/app/api/projects/[id]/tasks/route.ts:67-72](../src/app/api/projects/[id]/tasks/route.ts#L67-L72). `findFirst({ orderBy: { position: "desc" } })` then `task.create`. Should be one transaction with `aggregate({ _max: { position } })` + `create`, or switch to sparse fractional positions to avoid the lookup entirely.

#### P8 — No pagination anywhere
`GET /api/projects` returns every project the user is on, `GET /api/projects/:id` embeds every task, `GET /api/projects/:id/tasks` returns every row. Add `take` / `cursor` parameters before the dataset grows.

#### P15 — Position scheme has a rewrite cliff
`position: Int` means inserting between adjacent values requires shifting all following rows by +1. Fine today (no drag-drop UI), but a future drag-drop on a 500-task board would issue ~250 UPDATEs per drag. Switch to fractional indexing (`position: Float`) or a string-sortable key (`lexorank`) before that UI ships.

---

### 2.2 Sequential awaits / waterfalls

The recurring shape across the API: **getCurrentUser → getProjectMembership → actual query**. Three round-trips before any real work happens. Visible in every authenticated, project-scoped endpoint.

#### W1 — Merge auth + membership into one Prisma query
Both query by `user.id`. Replace `getCurrentUser` + `getProjectMembership` with a single `prisma.user.findUnique` that includes a filtered `memberships`. **3 RT → 2 RT** on every protected request. Combined with the cache layer (§2.3 C2/C3), most requests skip the DB for auth entirely.

#### W2 — Express auth as a WHERE clause on the data query
For `GET /api/projects/:id`: `prisma.project.findFirst({ where: { id, memberships: { some: { userId: user.id }}}, … })`. The auth check becomes a JOIN filter. **3 RT → 1 RT.** Bonus security: failure indistinguishable from "not found", killing the existence oracle.

#### W3, W4, W5 — Don't pre-check what the database can enforce
- `POST tasks`: collapse position lookup + create into one transaction or sparse positions. **4 RT → 1-2 RT.**
- `PATCH /api/tasks/:id` after the [A1+B1 security fixes](MASS_ASSIGNMENT_AUDIT.md): single `findUnique` with `project.memberships` filtered to `userId IN (caller, proposedAssignee)`. **5 RT → 2-3 RT.**
- `DELETE /api/tasks/:id`: express auth in `deleteMany({ where: { id, project: { memberships: { some: { userId, role: { in: …}}}}}})` — single statement does the auth and the delete; `count === 0` → 404. **3 RT → 1 RT.**

#### W6 — Register: drop the `findFirst` pre-check
After adding `email @unique`, replace the pre-check with a direct `create` + catch on `P2002`. **2 RT → 1 RT** and the [race condition (TOCTOU)](SECURITY_FINDINGS.md) is closed simultaneously.

#### W7 — `getCurrentUser` runs a DB lookup on every request
[src/lib/auth.ts:11-24](../src/lib/auth.ts#L11-L24). Reading the JWT alone is sufficient for most read paths. For paths that need to verify the user still exists, an LRU cache (§2.3 C2) makes the cost amortise to zero.

#### W8 — Login → dashboard cold start
Today: POST `/api/auth/login` (RT 1) → router push → mount dashboard → `useQuery` → GET `/api/projects` (RT 2). Pre-populate the `["projects"]` query cache from the login response and the dashboard's first paint is instant.

#### W10 — Task save → invalidate → full project refetch
6 RT user-visible. Optimistic update with rollback on failure makes this **0 RT user-visible**.

---

### 2.3 Caching gaps

The codebase has **one** cache layer: TanStack Query's in-memory map, per browser tab, with `staleTime: 30_000`. Every other layer is absent.

#### C1 — Add HTTP cache headers
No response sets `Cache-Control`. For per-user, soon-stale data: `Cache-Control: private, max-age=30, stale-while-revalidate=120` on `GET /api/projects`, `GET /api/projects/:id`, `GET /api/users/me`. Lets the browser short-circuit duplicate fetches and serve stale during background refresh.

#### C2 — Process-local LRU for read-mostly data
Add an `lru-cache` for `users` (60 s TTL) and `memberships` (30 s TTL). Combined with singleflight (§2.4 TH5), 100 concurrent requests for the same user collapse to 1 DB query, and subsequent requests for the TTL window are 0 DB queries. Memory cost: ~2 MB for 10k entries.

#### C3 — Request-scoped memoization
React 19's `cache()` for RSC, or a per-request `Map` for API routes. Within one request, multiple helpers reading the same row hit the DB once.

#### C4 — Per-query stale times with jitter
[src/components/QueryProvider.tsx:11](../src/components/QueryProvider.tsx#L11) is a single global. Per-query overrides:
- Project list — `staleTime: 5 * 60_000`.
- Current user — `staleTime: Infinity`.
- Add ±20% jitter to defaults so expiries don't synchronize.

#### C5 — Optional: persist TanStack cache to `localStorage` / `IndexedDB`
For heavy-navigation users, tab refresh is currently a cold start. `@tanstack/query-persist-client` adds disk-backed persistence. Trade-off: stale data on first paint; pair with a freshness header.

---

### 2.4 Thundering-herd risks

All inherit from the no-cache + no-coalescing posture. The first column says when this matters.

| # | Scenario | Triggers at |
|---|---|---|
| TH1 | 100 colleagues all open `/dashboard` near 9 AM; their TanStack caches expire within the same 30 s window | ~100 concurrent users |
| TH2 | Login storm — `bcryptjs` blocks the event loop, requests serialize on a single core | Today, any auth burst |
| TH3 | Real-time-ish board: one user edits, 10 viewers' tabs all invalidate + refetch the full project payload | Multi-user boards |
| TH4 | One user with 10 open tabs polls the same endpoint; `getCurrentUser` issues N identical user lookups | High per-user concurrency |
| TH5 | Multi-instance deployment with no Redis: every instance has its own LRU; they don't dedupe each other's DB calls | When > 1 Node instance |

#### TH5 — Singleflight pattern
For each in-flight `(operation, key)`, only one upstream query at a time. Trivial Map-based implementation works within one process; for multi-instance, Redis `SET NX EX` provides cross-instance coordination.

#### TH2 — Eliminated by P4 + login rate-limit
Once `bcryptjs` → native `bcrypt` (P4) and rate-limiting lands ([SECURITY_FINDINGS §4](SECURITY_FINDINGS.md)), TH2 dissolves: the work parallelizes (native bcrypt uses libuv's thread pool) and bursts are throttled at the door.

---

### 2.5 CPU / crypto

#### P4 — `bcryptjs` is pure JS, blocks the event loop
[package.json:24](../package.json#L24). Native `bcrypt` (or `@node-rs/bcrypt`) is ~3-4× faster and uses libuv's worker threads, so concurrent auth doesn't queue on the main thread. Existing hashes are format-compatible — drop-in replacement.

```bash
npm uninstall bcryptjs @types/bcryptjs
npm install bcrypt
```

Practical effect on a single-vCPU container: login throughput ceiling rises from ~5-10/sec to ~50/sec, and the event loop stays responsive during auth bursts. Pairs with TH2.

---

### 2.6 Frontend

#### P5 — Optimistic updates on task mutations
[src/components/TaskDetail.tsx:30-33](../src/components/TaskDetail.tsx#L30-L33), [src/app/projects/[id]/page.tsx:41-44](../src/app/projects/[id]/page.tsx#L41-L44). Replace `invalidateQueries` with `onMutate` + cache patch. UI updates immediately; the network call runs in the background; only roll back on failure.

#### W9 — Hover-prefetch
[src/app/dashboard/page.tsx:54-77](../src/app/dashboard/page.tsx#L54-L77). Add `onMouseEnter={() => queryClient.prefetchQuery({ … })}` on project cards. The fetch overlaps the user's mouse travel time → click feels instant.

#### W11 — Header reads localStorage in useEffect → blank-then-name flash
[src/components/Header.tsx:12-15](../src/components/Header.tsx#L12-L15). Read the user from `queryClient.getQueryData(["me"])` (pre-populated at login per W8) so the first render already has it.

#### P16 — No `React.memo` on `TaskCard`
With 200+ tasks on a board, every state change re-renders every card. `React.memo` + stable keys + `onClick` via `useCallback` cuts this. Not noticeable today.

#### P17 — `airtable` import discipline
The `airtable` dep (≈ 150 KB minified) is server-only. If anyone imports it from a `"use client"` component by accident, it ships to every browser visit. A lint rule (`import/no-restricted-paths`) or a code-review checklist item closes this.

---

### 2.7 Infrastructure

#### P11 — Prisma connection pool default
`new PrismaClient()` with no `connection_limit`. Default is `2 × CPU + 1`. On a single-vCPU container, that's 3 connections — easy to exhaust on burst. Set explicitly in `DATABASE_URL`: `?connection_limit=10&pool_timeout=20`.

#### P12 — Dockerfile uses `npm install`
[Dockerfile:10](../Dockerfile#L10). `npm ci` is faster and enforces lockfile fidelity. Build-time-only impact.

#### P13 — Turbopack only in dev
[package.json:6](../package.json#L6) — `next dev --turbopack`. `next build` still uses webpack. Optional; track the Turbopack-stable-for-build rollout in Next 15.x.

#### P14 — Compression
Next.js enables gzip by default for the Node server. Verify in production that any fronting proxy doesn't strip it; consider Brotli for large responses.

---

## 3. Remediation order (recommended)

Like the security report, this is sequenced so each tier multiplies the value of the next.

### Tier 1 — Cross-cutting wins (touch every protected route)

1. **W7 + C2 + C3** — replace `getCurrentUser` with a cached + JWT-first variant; add LRU for users/memberships. **Every authenticated request gets faster.**
2. **W1** — merge auth + membership into a single Prisma query in the helper. **3 RT → 2 RT** per request, **0 RT cached**.
3. **C1** — add `Cache-Control: private, max-age=30, stale-while-revalidate=120` to read-mostly GETs. Lets the browser short-circuit duplicate fetches.

### Tier 2 — Per-route waterfall collapses

4. **W2** — `GET /api/projects/:id` with auth-in-WHERE. **3 RT → 1 RT.**
5. **W4** — `PATCH /api/tasks/:id` with the membership join in the find. **5 RT → 2 RT** after security fixes.
6. **W5** — `DELETE /api/tasks/:id` via `deleteMany` with auth in WHERE. **3 RT → 1 RT.**
7. **W3** — `POST tasks` with one transaction or sparse positions. **4 RT → 2 RT** (or 1 with sparse).
8. **W6** — Register with `@unique` + P2002 catch. **2 RT → 1 RT** + race-condition fix.

### Tier 3 — Data shape & indexes

9. **P1** — `_count` on dashboard.
10. **P2** — explicit `select` clauses on project detail (also closes [A2](IDOR_AND_HASH_LEAK_AUDIT.md)).
11. **P3** — add the four missing indexes (also closes the [register race](SECURITY_FINDINGS.md)).
12. **P8** — paginate task list endpoints.

### Tier 4 — Frontend UX wins

13. **P5** — optimistic update on task mutations. **W10 vanishes.**
14. **W8** — pre-populate `["projects"]` cache from login response.
15. **W9** — hover-prefetch on project cards.
16. **W11** — read `me` from QueryClient cache, not `useEffect`.
17. **C4** — per-query staleTime + jitter.

### Tier 5 — CPU / herd

18. **P4** — swap `bcryptjs` → `bcrypt`. **TH2 dissolves.**
19. **TH5** — singleflight wrapper around the LRU layer.

### Tier 6 — Infra hygiene

20. **P11** — `connection_limit` in `DATABASE_URL`.
21. **P12** — `npm ci` in Dockerfile.
22. **P14** — verify compression is on in deployment.
23. **P15** — switch position to fractional indexing **before** drag-drop UI ships.
24. **C5** — TanStack persistence (only if you have heavy-navigation users).

---

## 4. What this codebase does well (for balance)

- **`findUnique` everywhere appropriate** — primary-key lookups always use the cheapest Prisma op.
- **Composite index `(projectId, status)`** is exactly what the Kanban board needs ([prisma/schema.prisma:85](../prisma/schema.prisma#L85)).
- **Singleton Prisma client** ([lib/prisma.ts:5-7](../src/lib/prisma.ts#L5-L7)) avoids the connection-explosion footgun that breaks many Next.js + Prisma tutorials.
- **TanStack Query with sane defaults** — `staleTime: 30_000`, `refetchOnWindowFocus: false`. Many apps ship `staleTime: 0` and burn requests on every render.
- **`select` discipline already in `getCurrentUser`** ([lib/auth.ts:21](../src/lib/auth.ts#L21)) — the right pattern is in the codebase, just needs applying elsewhere.
- **Single-file Prisma schema, single migration** — fast cold start, easy to reason about.

---

## 5. Cross-references

- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) — security findings, several of which share root causes with perf issues (P2/A2, P3/race condition, P4/TH2).
- [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md) — dependency CVEs.
- [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) — `$queryRawUnsafe` in task search.
- [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md) — XSS surface + token lifecycle.
- [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) — `passwordHash` leak shares the over-fetch root cause with P2.
- [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) — task PATCH waterfall worsens after this fix unless W4 is applied at the same time.

---

## 6. Measurement note

Before / after numbers in this report are based on round-trip-count analysis, not wall-clock benchmarks. Real measurements would need:

- Production-mode build (`next build && next start`) — `next dev` has additional overhead that masks real numbers.
- A populated dataset (e.g., 50 users, 20 projects, 500 tasks per project) — at seeded scale every endpoint returns in single-digit ms.
- A consistent client (`autocannon`, `wrk`, or `k6`) hitting the same endpoint at fixed concurrency.

A short benchmarking script is suggested:

```bash
# After applying a fix
npm run build && npm run start &
APP_PID=$!

# Warm up
for i in $(seq 1 10); do curl -s http://localhost:3000/api/projects > /dev/null; done

# Measure
autocannon -d 30 -c 20 -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/projects

kill $APP_PID
```

Run before and after each Tier-2 / Tier-3 fix to confirm the improvement.
