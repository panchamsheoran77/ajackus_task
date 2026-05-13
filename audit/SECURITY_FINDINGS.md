# Security Findings — Final Consolidated Report

**Project:** taskboard
**Date:** 2026-05-13
**Coverage:** Full-stack audit of [src/](../src/), [prisma/](../prisma/), Docker/CI surface, and dependency tree.
**Scope:** Authenticated and unauthenticated attack paths against a running instance at `http://localhost:3000` seeded via [prisma/seed.ts](../prisma/seed.ts).

This file is the entry point. Each finding either points to a dedicated companion report (for the ones with full PoCs already captured) or contains its own complete write-up below (for the ones that didn't get standalone files).

---

## 1. Summary table

| # | Finding | Severity | Status | Detailed report |
|---|---|---|---|---|
| 1 | Dependency CVEs (vitest RCE, Next.js SSRF/proxy bypass, postcss XSS, esbuild, eslint) | Critical / High / Mod | Proven via `npm audit` | [DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md) |
| 2 | SQL injection in task search → auth bypass + `users.password_hash` exfil | **Critical** | Proven end-to-end | [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md) |
| 3 | XSS surface latent + JWT in localStorage + zero rotation | **Critical** (chained) | Proven (incl. 2 live session-hijack vectors) | [XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md) |
| 4 | IDOR on `PATCH /api/tasks/:id` (A1) | **High** | Proven end-to-end | [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) |
| 5 | `passwordHash` returned by `GET /api/projects/:id` (A2) | **Critical** | Proven end-to-end | [IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md) |
| 6 | Mass-assignment / cross-project assignee on task PATCH (B1) | **Medium-High** | Proven end-to-end | [MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md) |
| 7 | Race condition on registration (no `@unique` on `users.email`) | **High** | Confirmed by inspection (§3) | this file |
| 8 | No rate limiting on `/api/auth/login`, `/api/auth/register`, or any other route | **High** | Proven on login (XSS_TOKEN_AUDIT §9.2); §4 below | this file + cross-ref |
| 9 | JWT missing `aud` / `iss` / `nbf` claims | Medium | Confirmed by inspection (§5) | this file |
| 10 | Email enumeration via `/api/auth/register` response | Medium | Confirmed by inspection (§6) | this file |

Findings 7–10 don't have separate report files; full reproducible details are in §3–§6 below.

---

## 2. Quick index of companion reports

- **[DEP_SECURITY_AUDIT.md](DEP_SECURITY_AUDIT.md)** — 10 vulnerabilities (1 critical, 1 high, 6 moderate, 2 low). All fixable inside their stated majors: `next@15.5.18`, `vitest@2.1.9`, `tsx@4.21.0`, `eslint@9.39.4`.
- **[SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md)** — `prisma.$queryRawUnsafe` on `GET /api/projects/:id/tasks?q=`. Two confirmed exploits:
  - Auth bypass — viewer reads tasks across projects via `q=%') OR 1=1 -- `.
  - UNION-based exfil of every user's bcrypt hash from `users.password_hash`.
- **[XSS_TOKEN_AUDIT.md](XSS_TOKEN_AUDIT.md)** — latent stored-XSS surface (no input sanitization, no CSP), JWT in localStorage with 30-day TTL and no revocation. Two independent **live** session-hijack vectors:
  - Login brute force — no rate limit, no lockout.
  - SQLi → bcrypt offline crack chain (see §2 SQLi above).
- **[IDOR_AND_HASH_LEAK_AUDIT.md](IDOR_AND_HASH_LEAK_AUDIT.md)** — two findings:
  - **A1**: `PATCH /api/tasks/:id` has no `getProjectMembership` check; viewer rewrote a task in a different project.
  - **A2**: `GET /api/projects/:id` includes `passwordHash` for every owner / member / assignee / creator (18 fields per response in the seeded DB).
- **[MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md)** — B1:
  - `assigneeId` accepted without verifying the assignee is a project member.
  - `200` vs `500` response codes form a user-existence oracle on candidate cuids.
  - Successful PATCH responses leak `name`+`email` of the targeted user.

---

## 3. Finding 7 — Race condition on registration (TOCTOU)

### 3.1 Where

[prisma/schema.prisma:24-26](../prisma/schema.prisma#L24-L26):

```prisma
model User {
  id           String   @id @default(cuid())
  email        String                          // ← no @unique
  name         String
  passwordHash String   @map("password_hash")
  …
}
```

[src/app/api/auth/register/route.ts:17-26](../src/app/api/auth/register/route.ts#L17-L26):

```ts
const existing = await prisma.user.findFirst({ where: { email } });
if (existing) {
  return badRequest("an account with that email already exists");
}

const passwordHash = await bcrypt.hash(password, 10);
const user = await prisma.user.create({
  data: { email, name, passwordHash },
  …
});
```

This is a textbook TOCTOU (time-of-check vs. time-of-use):

1. Two requests arrive concurrently with the same email.
2. Both call `findFirst` before either `create` completes → both see no existing user.
3. Both `create` succeed because the database has no uniqueness constraint to enforce.
4. The `users` table now contains two rows with the same email.

### 3.2 How it becomes exploitable

[src/app/api/auth/login/route.ts:16-20](../src/app/api/auth/login/route.ts#L16-L20):

```ts
const user = await prisma.user.findFirst({ where: { email } });
if (!user) return unauthorized("invalid credentials");

const ok = await bcrypt.compare(password, user.passwordHash);
```

`findFirst` returns one of the matching rows — Postgres ordering without `ORDER BY` is implementation-defined and depends on heap order / planner choice. So a victim and an attacker who both have rows with email `meera@taskboard.dev` will have logins succeed sometimes against the victim's password and sometimes against the attacker's password. With `findFirst`'s typical "first inserted, first returned" tendency, the attacker who registers AFTER the victim may not win — but if the attacker registers FIRST (e.g., during onboarding before the legitimate user signs up), the attacker's row sits first.

A simpler practical exploit: an attacker can register `meera@taskboard.dev` with their own password BEFORE the legitimate user does. The legitimate user is then prevented from registering ("already exists") and may file a support ticket — by which time the attacker has full control of the squatted account.

### 3.3 Reproducible commands

```bash
# Spawn N concurrent registrations of the same email; the absence of
# @unique means more than one can persist in the race window.
EMAIL="race-$(date +%s)@example.com"
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "$i:%{http_code} " -X POST http://localhost:3000/api/auth/register \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"P@ssword123!\",\"name\":\"Concurrent-$i\"}" &
done
wait; echo

# Check how many rows the table holds for that email
docker exec -i q-taskboard-assessment-db-1 \
  psql -U taskboard -d taskboard \
  -c "SELECT id, email, name, created_at FROM users WHERE email='$EMAIL';"
```

In practice the window depends on the Postgres connection-pool latency vs. the bcrypt hashing time; bcrypt cost 10 (≈ 100ms) is more than enough to overlap on a quiet local DB. Multiple successful 201s for the same email = the race triggered.

### 3.4 Fix

```prisma
model User {
  id           String   @id @default(cuid())
  email        String   @unique             // ← add this
  …
}
```

Then handle the unique-constraint violation in the register route:

```ts
try {
  const user = await prisma.user.create({ data: { email, name, passwordHash } });
  …
} catch (err) {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
    return badRequest("an account with that email already exists");
  }
  throw err;
}
```

The `findFirst` pre-check then becomes redundant and can be deleted. Also change `prisma.user.findFirst` to `prisma.user.findUnique` in the login route — once the column is unique, this is faster and signals intent. A data-cleanup migration is needed if the table already has duplicates.

---

## 4. Finding 8 — No rate limiting on any auth route

### 4.1 What's missing

There is no middleware in [src/middleware.ts](../src/middleware.ts) (the file does not exist). No rate-limiter library in [package.json](../package.json). No `Retry-After` header observed on any endpoint. No account lockout. No captcha.

### 4.2 Login — proven in companion report

Already demonstrated in [XSS_TOKEN_AUDIT.md §9.1](XSS_TOKEN_AUDIT.md):

> 30 wrong-password attempts in 10 seconds → all 401, zero 429, no `Retry-After`. Account still works after the bombardment.

At ~3 attempts/second from a single curl loop (bcrypt-CPU bound, not policy-bound), the seeded `password123` is found instantly against any common-password list.

### 4.3 Register — same gap

Same lack of throttling on `/api/auth/register`. An attacker can:

- Flood the `users` table with junk accounts to fill the DB and degrade query performance.
- Use the responses as an email-enumeration oracle at high speed (see Finding 10).
- Burn bcrypt CPU on the server (DoS via the cost-10 hash on every registration attempt).

Reproducible:

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "$i:%{http_code} " -X POST http://localhost:3000/api/auth/register \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"bot-$i@example.com\",\"password\":\"P@ss12345!\",\"name\":\"bot-$i\"}"
done; echo
# Expect 100 × 201, zero throttling.
```

### 4.4 Wider surface

Beyond `auth/*`, every state-changing endpoint runs at full speed:

- `POST /api/projects` — unlimited project creation.
- `POST /api/projects/:id/tasks` — unlimited task creation per project (already used in the XSS PoC to plant 5 payloads back-to-back with no friction).
- `PATCH /api/tasks/:id` — unlimited oracle probing (Finding 6 / B1).

### 4.5 Fix

Two layers:

1. **App-level limiter** for `auth/*`: e.g. `5 attempts / 15 min / (IP, email)` on login, exponential back-off after that; `5 registrations / 1 h / IP` on register. Options that fit Next.js App Router:
   - `@upstash/ratelimit` (Redis-backed; works in serverless).
   - `next-rate-limiter` or a hand-rolled in-memory limiter for single-process deployments.
2. **Account lockout** after N failed login attempts on a given email — even if the IP rotates. Combined with the email-enumeration fix in Finding 10, this prevents distributed brute force.

For non-auth routes, a simple per-IP cap (e.g. 100 req/min) at the edge (CDN / reverse proxy) is fine.

---

## 5. Finding 9 — JWT missing `aud` / `iss` / `nbf` claims

### 5.1 Where

[src/lib/jwt.ts](../src/lib/jwt.ts):

```ts
const EXPIRES_IN = "30d";

export type JWTPayload = {
  userId: string;
  email: string;
};

export function signToken(payload: JWTPayload): string {
  return jwt.sign(payload, SECRET as string, { expiresIn: EXPIRES_IN });
}

export function verifyToken(token: string): JWTPayload | null {
  try {
    const decoded = jwt.verify(token, SECRET as string) as JWTPayload;
    return decoded;
  } catch { return null; }
}
```

The resulting token carries only `userId`, `email`, `iat`, `exp`. There is no `aud` (audience), no `iss` (issuer), no `nbf` (not-before). The verify call sets no `algorithms` allow-list, no `audience`, no `issuer`.

### 5.2 Why it matters

- **Cross-environment replay.** If any deployment shares its `JWT_SECRET` with another environment (e.g., a staging cluster cloned from prod), tokens minted in one env validate in the other. `aud` + verified `audience` makes this fail closed: a token issued for `aud: "dev"` would not pass `audience: "prod"` verification even if the secret matched.
- **Issuer attribution.** Without `iss`, a future microservices split — or a third-party SDK using the same library — produces indistinguishable tokens. Verifying `iss === "taskboard-api"` makes tokens minted elsewhere reject cleanly.
- **No replay window control.** Without `nbf`, there's no way to issue a token "valid from time T" — useful for delayed access (e.g., scheduled offboarding) and for short-clock-skew safety. Minor compared to the other two.
- **No `algorithms` allow-list on verify.** `jsonwebtoken@9` rejects `alg: "none"` by default, but explicitly setting `algorithms: ["HS256"]` is best practice — it prevents future regressions if the library default ever changes or a downstream library override happens.

### 5.3 Compounding with already-proven issues

- Stolen tokens (from any of the two live hijack vectors in [XSS_TOKEN_AUDIT.md §9](XSS_TOKEN_AUDIT.md)) survive for the full 30 days. `nbf` doesn't change this — the right fix is the rotation/revocation work in [XSS_TOKEN_AUDIT.md §9.4](XSS_TOKEN_AUDIT.md) — but adding `aud`/`iss` is a cheap independent step.

### 5.4 Reproducible — decode an existing token

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"meera@taskboard.dev","password":"password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

python3 - <<PY
import base64, json
p = "$TOKEN".split('.')[1]
p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
PY
```

Expected output:

```json
{
  "userId": "cmp3q9s080000mh5r0r4n5m4d",
  "email": "meera@taskboard.dev",
  "iat": 1778…,
  "exp": 1781…
}
```

No `aud`, `iss`, `nbf`.

### 5.5 Fix

```ts
// jwt.ts
const ISSUER = process.env.JWT_ISSUER ?? "taskboard-api";
const AUDIENCE = process.env.JWT_AUDIENCE ?? "taskboard-web";

export function signToken(payload: JWTPayload): string {
  return jwt.sign(payload, SECRET as string, {
    expiresIn: "15m",                   // ← drop TTL; pair with refresh flow
    issuer: ISSUER,
    audience: AUDIENCE,
    notBefore: 0,
    algorithm: "HS256",
  });
}

export function verifyToken(token: string): JWTPayload | null {
  try {
    return jwt.verify(token, SECRET as string, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["HS256"],
    }) as JWTPayload;
  } catch {
    return null;
  }
}
```

Combine with the rotation/revocation recommendations from [XSS_TOKEN_AUDIT.md §9.4](XSS_TOKEN_AUDIT.md):
- Drop access-token TTL to 15 min, add refresh-token flow.
- Add `jti` + revocation list; add `tokenVersion` on `User`.

---

## 6. Finding 10 — Email enumeration via `/api/auth/register`

### 6.1 Where

[src/app/api/auth/register/route.ts:17-20](../src/app/api/auth/register/route.ts#L17-L20):

```ts
const existing = await prisma.user.findFirst({ where: { email } });
if (existing) {
  return badRequest("an account with that email already exists");
}
```

The endpoint distinguishes between "email is taken" (HTTP 400, `"an account with that email already exists"`) and "email is free" (HTTP 201, account created). This is a clean yes/no oracle on whether a given email is registered.

Login, by comparison, uniformly returns `"invalid credentials"` ([api/auth/login/route.ts:17-20](../src/app/api/auth/login/route.ts#L17-L20)) — good. The register endpoint is the leak.

### 6.2 Why it matters

- **User enumeration before any other attack.** An attacker preparing for credential stuffing or phishing can build a verified list of registered emails by probing register one-at-a-time.
- **Side effect: account squatting.** A "fresh" email is not just probed — the register call creates a real account. The attacker can register every plausible email of a target organisation (using common-name patterns) and lock legitimate users out (compare Finding 7 — without the race condition, the second registration is blocked, so the squatted accounts cannot be displaced by legitimate registration).
- **Pairs with no rate-limit (Finding 8):** thousands of emails per second.
- **Pairs with the B1 oracle ([MASS_ASSIGNMENT_AUDIT.md](MASS_ASSIGNMENT_AUDIT.md)):** that one enumerates userIds; this one enumerates emails. Together: a complete map.

### 6.3 Reproducible commands

```bash
# Probe a known-existing seed email
curl -s -o /dev/null -w "existing: HTTP %{http_code}\n" -X POST \
  http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"meera@taskboard.dev","password":"P@ssword123!","name":"X"}'

# Probe a fresh email (also CREATES THE ACCOUNT — side effect)
curl -s -o /dev/null -w "fresh   : HTTP %{http_code}\n" -X POST \
  http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"fresh-$(date +%s)@example.com\",\"password\":\"P@ssword123!\",\"name\":\"X\"}"
```

Expected: `existing: HTTP 400`, `fresh: HTTP 201`. Single-bit oracle, no friction.

### 6.4 Fix

Two parts:

1. **Constant response for register.** Always return `200` (or `202`) with a body that says "if this email is not yet registered, you will receive a confirmation email." Defer the actual account creation to an email-verification step. This is the standard mitigation; it also fixes the side-effect-creates-account aspect of the leak.
2. **Constant timing.** When the response shape no longer leaks, make sure timing doesn't either. Hash a dummy password on the "already taken" path so bcrypt cost runs in both branches.

If switching to email verification is too disruptive for the assessment scope, the minimum acceptable fix is:

- Return `400 "registration is currently invitation-only"` (or similar generic message) for the duplicate-email case.
- Add rate limiting (Finding 8).

This degrades signal quality enough that mass enumeration becomes impractical without solving the underlying flow.

---

## 7. Remediation order (recommended)

Sequence matters because some fixes invalidate active exploit chains while others depend on each other.

**Tier 1 — apply before anything else (closes live exploitable paths):**

1. **Bump dependencies** to the versions in [DEP_SECURITY_AUDIT.md §Action](DEP_SECURITY_AUDIT.md) (`next@15.5.18`, `vitest@2.1.9`, `tsx@4.21.0`, `eslint@9.39.4`). Closes the Next.js prod-surface SSRF / cache-poisoning / proxy-bypass chain and the vitest dev RCE. Cost is four version pins inside the stated majors.
2. **Fix the SQL injection** at [src/app/api/projects/[id]/tasks/route.ts:25-36](../src/app/api/projects/[id]/tasks/route.ts#L25-L36) — replace `$queryRawUnsafe` with the structured `findMany`. (Closes auth bypass + bcrypt-hash exfil. See [SQL_INJECTION_AUDIT.md §9.1](SQL_INJECTION_AUDIT.md).)
3. **Stop returning `passwordHash`** from `GET /api/projects/:id` — add explicit `select` clauses and a schema-level `omit` on `passwordHash`. (See [IDOR_AND_HASH_LEAK_AUDIT.md §2.5](IDOR_AND_HASH_LEAK_AUDIT.md).)
4. **Force a password reset for every existing user.** Their hashes have already been observable since both #2 and #3 leak them.

**Tier 2 — auth/auth hardening:**

5. **Add membership + role check on `PATCH /api/tasks/:id`** (Finding 4 / A1) and the assignee-membership check (Finding 6 / B1). Single combined diff covered in [MASS_ASSIGNMENT_AUDIT.md §8.1](MASS_ASSIGNMENT_AUDIT.md).
6. **Add `@unique` on `users.email`** (Finding 7) and handle P2002 from register.
7. **Add rate limiting** to `auth/*` and a generic per-IP cap on state-changing routes (Finding 8).
8. **Standardise register response** to remove the email-enumeration oracle (Finding 10).

**Tier 3 — token lifecycle:**

9. **Shorten access-token TTL to 15 min, add a refresh-token flow** in `httpOnly; Secure; SameSite=Strict` cookies; move the access token off `localStorage`. (See [XSS_TOKEN_AUDIT.md §7.2](XSS_TOKEN_AUDIT.md).)
10. **Add `aud`, `iss`, `nbf` claims and verify them** on both sign and verify (Finding 9). Pin `algorithms: ["HS256"]` on verify.
11. **Add `jti` + revocation table** and `tokenVersion` on `User`. Implement `POST /api/auth/logout` that uses them.

**Tier 4 — defence in depth:**

12. **Add a CSP** and other security headers; add ESLint `react/no-danger`. (See [XSS_TOKEN_AUDIT.md §7.1](XSS_TOKEN_AUDIT.md).)
13. **Audit-log** every PATCH/DELETE on tasks and projects.
14. **DB-level CHECK** that any non-null `tasks.assignee_id` exists in `memberships` for the same `project_id`. (See [MASS_ASSIGNMENT_AUDIT.md §8.3](MASS_ASSIGNMENT_AUDIT.md).)

---

## 8. Test data state

Every PoC across these reports was performed against the seeded DB and either:

- Restored to seeded values inline (admin PATCH revert), or
- Left behind a small, identified artifact that can be wiped with `npm run db:reset`.

The DB right now contains the seed-quirk side-effects only (e.g. the 5 XSS-payload tasks under Internal Tools Cleanup from [XSS_TOKEN_AUDIT.md §8](XSS_TOKEN_AUDIT.md)). To return to a perfectly clean state for a fresh assessment run:

```bash
docker-compose exec web npm run db:reset
```

---

## 9. Method recap

For each finding the audit followed the same shape used throughout this session:

1. **Static analysis** — `grep` for sink patterns (`$queryRawUnsafe`, `dangerouslySetInnerHTML`, `include: true`, unbounded `assigneeId`, etc.) and read the matched files in full.
2. **Schema review** — [prisma/schema.prisma](../prisma/schema.prisma), [src/schemas/*.ts](../src/schemas), and [src/types/index.ts](../src/types/index.ts).
3. **Live PoC** — login as the least-privileged seeded user that can demonstrate the path, run the exploit, cross-check the result through an independent channel (direct `psql` query against the running Postgres container), then restore.
4. **Cross-reference** — every finding's compound effects with the other findings are called out, since the impact of any one is amplified by the others.
