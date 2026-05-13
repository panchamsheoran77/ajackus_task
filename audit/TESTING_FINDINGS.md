# Testing Analysis

**Project:** taskboard
**Date:** 2026-05-13
**Scope:** existing test suite, harness configuration, coverage gaps, and the relationship between test posture and the bugs already found in this audit series.
**Verdict:** the project ships **3 test files / 10 test cases / ~50 lines of test code**, all of them pure-function or component-rendering smoke tests. Every audit finding in this series (SQLi, IDOR, password-hash leak, mass-assignment, race condition, perf waterfalls, integrity gaps) would have been caught by basic API-level tests — none of which exist.

---

## 1. Executive summary

The harness is well-chosen (Vitest 2 + Testing Library + jsdom + `@/` alias). Its application is shallow.

### What's there

| File | Tests | Targets |
|---|---|---|
| [src/tests/auth.test.ts](../src/tests/auth.test.ts) | 2 | `signToken` / `verifyToken` round-trip + invalid token |
| [src/tests/schemas.test.ts](../src/tests/schemas.test.ts) | 5 | Positive/negative cases on register, login, create-task, update-task Zod schemas |
| [src/tests/TaskCard.test.tsx](../src/tests/TaskCard.test.tsx) | 3 | Renders title + assignee; falls back to "unassigned"; calls `onClick` |
| [src/tests/setup.ts](../src/tests/setup.ts) | — | Sets `JWT_SECRET` for tests; imports `jest-dom` matchers |
| [vitest.config.ts](../vitest.config.ts) | — | jsdom global, `globals: true`, `@/` alias |

**~10 test cases for a full-stack app of ~12 route handlers, 5 React pages, 5 components, 4 Zod schemas, and 4 Prisma models.**

### What's not

- Zero API route tests (no test imports any `route.ts`).
- Zero database / repository tests.
- Zero integration tests (route → Prisma → response).
- Zero E2E tests (no Playwright / Cypress).
- Zero security regression tests.
- Zero authorization tests (the very class of bug responsible for [A1 IDOR](IDOR_AND_HASH_LEAK_AUDIT.md) and [B1 mass-assignment](MASS_ASSIGNMENT_AUDIT.md)).
- Zero contract / response-shape tests (which would have caught [A2 password-hash leak](IDOR_AND_HASH_LEAK_AUDIT.md)).
- Zero CI configuration — tests are never automatically run.
- Zero coverage measurement.
- Zero load / performance benchmarks.

### Coverage math (estimated)

There is no `vitest --coverage` configured. By reading the test files: pure-logic coverage of `lib/jwt.ts` and `schemas/*.ts` is fair; coverage of route handlers, `lib/auth.ts` (beyond what jwt tests touch), `lib/prisma.ts`, `lib/api-client.ts`, every page, every component except `TaskCard`, and the Prisma schema constraints is **zero**.

---

## 2. What the existing tests do well — for balance

- **TaskCard tests use the right pattern** — Testing Library queries by visible text and role, not by class or `data-testid`. Behavioural, not implementation-coupled.
- **Zod schemas have positive and negative cases** — `accepts a well-formed register payload` + `rejects short passwords` etc. The shape is right.
- **`setupFiles` correctly imports `jest-dom/vitest` matchers** so `toBeInTheDocument` works.
- **`@/` path alias is configured** in vitest, matching the production tsconfig.
- **Vitest is a strong default** for this stack — fast, ESM-native, TypeScript-first, Vite-aligned.

The foundation is fine; the build-on-top is missing.

---

## 3. Gaps

### 3.1 No tests at the layer where bugs actually happen

Every finding documented in this audit series sits in **route handlers**, not in the helpers and schemas that the existing tests cover. Mapping:

| Audit finding | What test would have caught it |
|---|---|
| [SQLi in task search](SQL_INJECTION_AUDIT.md) | Route test: `GET /api/projects/:id/tasks?q=%27%20OR%201%3D1%20--` returns only the caller's tasks (or returns the same row set as `q=`) |
| [A1 IDOR on task PATCH](IDOR_AND_HASH_LEAK_AUDIT.md) | Route test: viewer-of-another-project sends PATCH → expect 403, parallel to existing DELETE behaviour |
| [A2 `passwordHash` leak](IDOR_AND_HASH_LEAK_AUDIT.md) | Contract test: response JSON of `GET /api/projects/:id` contains no string matching `/^\$2[ayb]\$/` |
| [B1 cross-project assignee](MASS_ASSIGNMENT_AUDIT.md) | Route test: PATCH with `assigneeId` pointing at a non-member → expect 400 |
| [Register race / no `@unique`](SECURITY_FINDINGS.md) | Concurrency test: two parallel POSTs with the same email → expect exactly one 201 |
| [Email case-insensitive dup](DATA_INTEGRITY_FINDINGS.md) D4 | Schema test asserting `registerSchema.parse({ email: "X@Y.com" })` produces `email: "x@y.com"` |
| [`position` collision](DATA_INTEGRITY_FINDINGS.md) D5 | Concurrent task-creation test asserting `position` is unique per `(project, status)` |
| [No optimistic concurrency](DATA_INTEGRITY_FINDINGS.md) D11 | Test: two PATCHes with the same `version` — one succeeds, the other 409s |
| [No rate limiting](SECURITY_FINDINGS.md) | After-N-failures test: the 6th login attempt within a window returns 429 |
| [JWT missing `aud`/`iss`](SECURITY_FINDINGS.md) | Token-decode test: payload includes `aud === "taskboard-web"`, `iss === "taskboard-api"` |
| [Waterfall API calls](PERFORMANCE_FINDINGS.md) | Round-trip-count test: `expect(prismaSpy.queries).toHaveLength(<=2)` per request |

A route handler under Vitest with a real test database is doable in ~15 lines of setup. Catching all of the above in one weekend is realistic.

### 3.2 No route-handler tests at all

Next.js App Router route handlers are exportable functions: `GET`, `POST`, etc. They take a `NextRequest` and return a `NextResponse`. **They're directly testable.** Today, none are tested.

Example shape that would close the gap:

```ts
// src/tests/api/tasks.idor.test.ts
import { PATCH } from "@/app/api/tasks/[id]/route";
import { resetDb, seedFixtures } from "./helpers/db";
import { newRequest, mintToken } from "./helpers/http";

describe("PATCH /api/tasks/:id authorization", () => {
  beforeEach(() => resetDb());

  it("forbids non-members from editing tasks (regression for A1 IDOR)", async () => {
    const { devToken, onboardingTaskId } = await seedFixtures();
    const req = newRequest(`http://x/api/tasks/${onboardingTaskId}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${devToken}` },
      body: { title: "should-not-stick" },
    });
    const res = await PATCH(req, { params: Promise.resolve({ id: onboardingTaskId }) });
    expect(res.status).toBe(403);
  });

  it("forbids assignment to a non-member (regression for B1)", async () => {
    /* ... */
  });
});
```

The harness already supports this. The missing pieces are:
- A real (or in-memory) database connection for tests.
- Per-test reset / transactional rollback.
- A token-minting helper.
- A `NextRequest` factory.

### 3.3 No database for tests

[docker-compose.yml:28-39](../docker-compose.yml#L28-L39) defines a `test` service pointing at `taskboard_test`, but no test file connects to it. The existing tests run against an empty Postgres expectation (vitest is jsdom-only).

Two pragmatic options:

**Option A — real Postgres, transactional rollback per test.**
```ts
// helpers/db.ts
import { PrismaClient } from "@prisma/client";
export const prisma = new PrismaClient();

export async function withTx<T>(fn: (tx: PrismaClient) => Promise<T>) {
  return prisma.$transaction(async (tx) => {
    await fn(tx as PrismaClient);
    throw new ROLLBACK();  // intentional throw to roll back
  }).catch((e) => { if (!(e instanceof ROLLBACK)) throw e; });
}
class ROLLBACK extends Error {}
```
Slower per-test (~50 ms) but exercises the real query planner, real constraints, real cascade rules.

**Option B — in-memory SQLite via `@prisma/adapter-libsql` or `pg-mem`.**
Faster but introduces dialect drift — Postgres-specific features (citext, partial unique indexes, `ILIKE`, the `TaskStatus` enum) behave differently.

For a project this size with Postgres-specific schema features, **Option A** is the safer pick.

### 3.4 No CI integration

No `.github/workflows/`, no `circle.yml`, no `gitlab-ci.yml`. The `.git-hooks/pre-commit` (per the README) auto-captures AI conversations but doesn't run `npm test`. So:

- A regression introduced by a contributor isn't caught before merge.
- The test suite is only run when someone manually runs `npm test`.
- Coverage drift is invisible.

**Fix:** trivial GitHub Actions workflow:

```yaml
# .github/workflows/ci.yml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env: { POSTGRES_USER: taskboard, POSTGRES_PASSWORD: taskboard, POSTGRES_DB: taskboard_test }
        ports: ["5432:5432"]
        options: --health-cmd pg_isready --health-interval 10s
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20", cache: "npm" }
      - run: npm ci
      - run: npx prisma migrate deploy
        env: { DATABASE_URL: postgresql://taskboard:taskboard@localhost:5432/taskboard_test }
      - run: npm run lint
      - run: npm run typecheck
      - run: npm test -- --coverage
        env:
          DATABASE_URL: postgresql://taskboard:taskboard@localhost:5432/taskboard_test
          JWT_SECRET: test-secret-${{ github.run_id }}
```

### 3.5 No coverage reporting / threshold

[vitest.config.ts](../vitest.config.ts) has no `coverage` section. Without it:

- No empirical answer to "what fraction of the codebase is covered?"
- No way to enforce that PRs don't lower coverage.
- No way to spot files that have zero tests (e.g., every `route.ts`).

**Fix:**

```ts
// vitest.config.ts
test: {
  // ...
  coverage: {
    provider: "v8",
    reporter: ["text", "lcov", "html"],
    include: ["src/**/*.{ts,tsx}"],
    exclude: ["src/tests/**", "src/**/*.test.{ts,tsx}", "**/*.d.ts"],
    thresholds: {
      lines: 50,         // start low, ratchet up
      functions: 50,
      branches: 40,
      statements: 50,
      perFile: false,
    },
  },
},
```

### 3.6 No test factories / fixtures

`TaskCard.test.tsx` inlines `baseTask`. Future route tests will repeat the same structure for User, Project, Membership, Task. Without factories this gets unwieldy fast.

```ts
// src/tests/helpers/factories.ts
let counter = 0;
const next = () => `t_${++counter}`;

export const makeUser = (over: Partial<User> = {}): User => ({
  id: next(),
  email: `user-${next()}@example.com`,
  name: "Test User",
  passwordHash: "$2a$10$fakehashforfakeuser",
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over,
});

export const makeTask = (over: Partial<Task> = {}): Task => ({ /* ... */ });
```

`@faker-js/faker` if you want randomized inputs; not strictly needed.

### 3.7 No security-regression test suite

Every PoC in this audit series should become a regression test. They are by definition the cases someone has already verified are bugs — letting them recur silently is worse than not finding them in the first place. Suggested file: `src/tests/security/regression.test.ts`:

```ts
import { describe, it, expect } from "vitest";
// + harness imports

describe("security regressions", () => {
  it("SQLi: task search does not bypass project scope", async () => { /* ... */ });
  it("A1 IDOR: non-member PATCH returns 403", async () => { /* ... */ });
  it("A2: GET /api/projects/:id contains no bcrypt hash", async () => {
    const body = await getProject(memberToken, projectId);
    const json = JSON.stringify(body);
    expect(json).not.toMatch(/\$2[ayb]\$/);
  });
  it("B1: cross-project assignee is rejected", async () => { /* ... */ });
  it("Race: concurrent registers produce exactly one user", async () => { /* ... */ });
  it("JWT: payload contains iss + aud", async () => { /* ... */ });
});
```

This file becomes a load-bearing artifact of the audit. Any future PR that re-opens any of these failures fails CI immediately.

### 3.8 No contract / snapshot tests on API responses

Even without integration tests, **snapshot tests on representative responses** catch shape drift cheaply. Would have caught the [A2 passwordHash leak](IDOR_AND_HASH_LEAK_AUDIT.md) the moment it was introduced, because the snapshot would have included the field.

```ts
it("GET /api/projects/:id matches the documented shape", async () => {
  const body = await getProject(memberToken, projectId);
  expect(body).toMatchInlineSnapshot();
});
```

Pair with a schema-validation library (`zod`'s own `parse()` against an output schema) for stronger guarantees.

### 3.9 No E2E tests for critical journeys

Playwright is the obvious choice. Two-to-three E2E specs would cover the unhappy paths the unit/integration tier misses (browser-only behaviour, localStorage handling, the React-Query cache, navigation):

```ts
// e2e/critical.spec.ts
test("login → dashboard → open project → create task → see it on board", async ({ page }) => { /* ... */ });
test("logout clears the bearer token and redirects to /login", async ({ page }) => { /* ... */ });
test("non-member cannot reach a project page", async ({ page }) => { /* ... */ });
```

Run on a separate `e2e:` script with a longer timeout; not part of every `npm test`.

### 3.10 No load tests / benchmarks

[PERFORMANCE_FINDINGS.md §6](PERFORMANCE_FINDINGS.md) suggests `autocannon` for measuring fix impact. Worth committing as a script:

```json
// package.json
"scripts": {
  "bench:projects": "autocannon -d 30 -c 20 -H \"Authorization: Bearer $TOKEN\" http://localhost:3000/api/projects"
}
```

For per-function microbench, Vitest 2's `bench()` works:

```ts
import { bench, describe } from "vitest";
describe("bcrypt", () => {
  bench("hash cost 10", async () => { await bcrypt.hash("password", 10); });
});
```

Useful before/after the `bcryptjs → bcrypt` swap proposed in [PERFORMANCE_FINDINGS P4](PERFORMANCE_FINDINGS.md).

### 3.11 No property-based tests

For the integrity invariants in [DATA_INTEGRITY_FINDINGS.md](DATA_INTEGRITY_FINDINGS.md), property tests with `fast-check` express the rule directly:

```ts
import fc from "fast-check";
test("task positions are unique within (project, status) regardless of insert order", async () => {
  await fc.assert(fc.asyncProperty(
    fc.array(fc.constantFrom("todo","in_progress","review","done"), { minLength: 0, maxLength: 100 }),
    async (statuses) => {
      // create N tasks with given statuses in parallel, then assert uniqueness
    }
  ));
});
```

Property tests are how you express "for all valid inputs, this invariant holds" without enumerating every case.

### 3.12 Configuration issues

- **`environment: "jsdom"` is global.** jsdom is needed only for component tests. Per-file directives (`// @vitest-environment node`) on API/schema/util tests would be faster.
- **`globals: true`** — every test file in the repo currently imports `describe`/`it`/`expect` anyway, so this is unused. Either remove it (forces explicit imports — better hygiene), or remove the explicit imports (less typing). Pick one.
- **No `testTimeout` / `hookTimeout`** — fine for unit tests; once integration tests hit a DB, default 5 s may be tight on cold start. Bump to 30 s for integration-tagged tests.
- **No parallelism config for integration tests.** When the DB-using tests appear, parallel runs against a single shared DB will conflict. Either: per-worker schema (`POOL=test_$WORKER_ID`), or `--pool=forks --poolOptions.forks.singleFork=true` for integration only.

---

## 4. The relationship to the other findings reports

Every other report in this series points at testing as the missing safety net. Read across them:

| Other report | Testing implication |
|---|---|
| [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) | 10 vulnerabilities, every one preventable by a single API-level test |
| [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md) | Round-trip-count tests + bench scripts would have flagged the waterfalls and herd risks |
| [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md) | The lack of a use-case layer is why route tests are hard; introducing the layer makes use cases testable in pure form (no Prisma needed) |
| [DATA_INTEGRITY_FINDINGS.md](DATA_INTEGRITY_FINDINGS.md) | Most integrity invariants are best expressed as property tests; the second-best place is DB constraints (tested via the DB tier) |

The architecture refactor proposed in [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md) directly enables the testing wins here:

- Once **use cases** exist as plain functions, they're testable with in-memory port implementations — no DB, no jsdom, no `NextRequest`. The unit-test layer gets fast and broad.
- Once **repository ports** exist, integration tests substitute the Prisma adapter for a fake, drastically simplifying setup.
- Once **domain entities** carry their invariants, the invariant tests live alongside the entities (`task.test.ts` tests `Task.reassign()` directly).

In other words: the testing improvements and the architecture refactor are the same project from two angles.

---

## 5. Suggested test pyramid for this project

Given the codebase size, a sensible target distribution:

| Layer | Count target | What goes here | Speed |
|---|---|---|---|
| **Pure unit** | 60-80 | Schemas, value objects, domain entities (post-refactor), pure helpers, components | < 1 s total |
| **Application unit** | 20-30 | Use cases with in-memory ports (post-refactor) | < 5 s total |
| **API integration** | 20-30 | Route handlers against a real Postgres with transactional rollback | < 30 s total |
| **E2E** | 5-10 | Critical user journeys via Playwright against a running server | < 60 s total |
| **Benchmarks** | 3-5 | bcrypt, route latency, payload size | Manual / nightly |

Today the project is roughly: pure unit ~10, everything else 0.

---

## 6. Remediation roadmap

### Tier 1 — Set the floor (1 day)

1. **Add coverage reporting** to `vitest.config.ts`. Set thresholds at the current level so they don't regress.
2. **Add a CI workflow** that runs `npm run lint`, `npm run typecheck`, `npm test -- --coverage`.
3. **Write the security regression test file** ([§3.7](#37-no-security-regression-test-suite)) with one `it.todo()` per finding so the gaps are visible.

### Tier 2 — Build the integration tier (2-3 days)

4. **Test-database helpers** ([§3.3](#33-no-database-for-tests)): connection, per-test reset, transactional rollback, fixture seeding.
5. **HTTP helpers**: `newRequest`, `mintToken`, response-asserting matchers.
6. **Factories** for User, Project, Membership, Task.
7. **Fill the API integration tier** — one test file per route handler. Cover the happy path and one or two unhappy paths each. Convert each `it.todo()` from Tier 1 step 3 into a real test.

### Tier 3 — Wire in the deeper layers (1-2 days)

8. **Contract / snapshot tests** on every read endpoint's response shape (catches future leaks like A2).
9. **Property tests** for the integrity invariants from [DATA_INTEGRITY_FINDINGS.md](DATA_INTEGRITY_FINDINGS.md) (D5 position uniqueness, D11 optimistic concurrency, D14 email normalisation).
10. **E2E tier with Playwright** — login + dashboard + create task + open project happy path.

### Tier 4 — Performance & maturity (ongoing)

11. **Bench script** for bcrypt cost / route latency, run on demand before/after fixes from [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md).
12. **Mutation testing** with Stryker, optional. Useful once the test suite is dense enough to be worth grading.
13. **Coverage threshold ratchet** — increase the floor by 5% every sprint until it's at a target.

---

## 7. What this codebase does well (for balance, second pass)

Worth saying again, more concretely:

- The choice of **Vitest over Jest** for a Next.js + TypeScript app is correct: faster, ESM-native, less config drift.
- The choice of **Testing Library over Enzyme** is correct: behavioural tests over implementation tests.
- The `setupFiles` pattern is in place — adding new globals or matchers is one line.
- The `@/` path alias is consistent between tsconfig, vitest, and Next.js — tests look like production code.
- The 10 tests that exist are **idiomatic and well-shaped**. Whoever wrote them knew what they were doing; they just didn't write enough of them.

So the work ahead isn't "fix the tests"; it's "extend their scope to the layers that hold the bugs".

---

## 8. Cross-references

- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md), [PERFORMANCE_FINDINGS.md](PERFORMANCE_FINDINGS.md), [ARCHITECTURE_FINDINGS.md](ARCHITECTURE_FINDINGS.md), [DATA_INTEGRITY_FINDINGS.md](DATA_INTEGRITY_FINDINGS.md) — the four consolidated reports whose findings should become the bulk of the security/integration regression test suite.
- [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md), [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md), [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md), [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md), [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) — PoC reports; each PoC is a candidate `it()` block for `tests/security/regression.test.ts`.
