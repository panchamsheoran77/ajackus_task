# Dependency Security Audit

**Project:** taskboard
**Date:** 2026-05-13
**Source:** `npm audit` against `package-lock.json` (GitHub Advisory Database)
**Totals:** 10 vulnerabilities — 1 critical, 1 high, 6 moderate, 2 low
**Fix scope:** All issues resolvable without crossing a stated major; no `--force` upgrades required.

## Summary Table

| Package | Current | Fix Version | Severity | Direct? | Notes |
|---|---|---|---|---|---|
| vitest | 2.1.8 | **2.1.9** | Critical | direct (dev) | RCE — pulls fixes for vite/@vitest/mocker/vite-node/esbuild |
| next | 15.5.15 | **15.5.18** | High | direct | 13 advisories rolled in; also fixes transitive postcss |
| postcss | <8.5.10 | **8.5.10** | Moderate | transitive (next) | Fixed by next bump |
| tsx | 4.19.2 | **4.21.0** | Moderate | direct (dev) | Pulls fix for esbuild |
| eslint | 9.17.0 | **9.39.4** | Low | direct (dev) | Fixes transitive @eslint/plugin-kit |

---

## Critical

### vitest 2.1.8 → 2.1.9
- **GHSA-9crc-q9x8-hgqq** (CVSS 9.6) — Remote Code Execution: a malicious website can reach a developer's running Vitest API server and execute code. Affected range `>=2.0.0 <2.1.9`.
- Transitively closes:
  - `@vitest/mocker <=3.0.0-beta.4`
  - `vite <=6.4.1` — **GHSA-4w7w-66w2-5vf9** (path traversal in optimized-deps `.map` handling)
  - `vite-node <=2.2.0-beta.2`
  - `esbuild <=0.24.2` — **GHSA-67mh-4wv8-2f99** (CVSS 5.3, dev server lets any website send requests and read responses)

## High

### next 15.5.15 → 15.5.18
Thirteen advisories collapse into a single same-minor patch bump.

| GHSA | CVSS | Title |
|---|---|---|
| GHSA-c4j6-fc7j-m34r | 8.6 | SSRF in apps using WebSocket upgrades |
| GHSA-492v-c6pp-mqqv | 8.1 | Middleware/Proxy bypass via dynamic route parameter injection |
| GHSA-267c-6grr-h53f | 7.5 | Middleware/Proxy bypass via segment-prefetch routes |
| GHSA-26hh-7cqf-hhc6 | 7.5 | Segment-prefetch bypass — incomplete fix follow-up |
| GHSA-36qx-fr4f-26g5 | 7.5 | Middleware/Proxy bypass in Pages Router i18n |
| GHSA-mg66-mrh9-m8jx | 7.5 | DoS via connection exhaustion (Cache Components) |
| GHSA-8h8q-6873-q5fj | 7.5 | DoS with Server Components |
| GHSA-gx5p-jg67-6x7h | 6.1 | XSS in `beforeInteractive` scripts with untrusted input |
| GHSA-h64f-5h5j-jqjh | 5.9 | DoS in Image Optimization API |
| GHSA-wfc6-r584-vfw7 | 5.4 | Cache poisoning in RSC responses |
| GHSA-ffhc-5mcf-pf4q | 4.7 | XSS in App Router apps using CSP nonces |
| GHSA-vfv6-92ff-j949 | 3.7 | Cache poisoning via collisions in RSC cache-busting |
| GHSA-3g8h-86w9-wvmq | 3.7 | Middleware/Proxy redirects can be cache-poisoned |

## Moderate

### postcss → 8.5.10 (transitive via next)
- **GHSA-qx2v-qp2m-jg93** (CVSS 6.1) — XSS via unescaped `</style>` in CSS stringify output. Resolved by `next@15.5.18`.

### tsx 4.19.2 → 4.21.0
- Inherits **GHSA-67mh-4wv8-2f99** through bundled `esbuild <=0.24.2`. Bump closes it.

## Low

### eslint 9.17.0 → 9.39.4
- **GHSA-xffm-g5w8-qvg7** — ReDoS in `@eslint/plugin-kit` `ConfigCommentParser`. Dev-only impact.

---

## Recommended Action

Pin the four direct upgrades explicitly (safer than `npm audit fix --force`, which may touch peers):

```bash
npm install next@15.5.18 vitest@2.1.9 tsx@4.21.0 eslint@9.39.4
npm audit                # expect: 0 vulnerabilities
npm test
npm run build
```

All four stay within the majors advertised in the README's tech stack (Next.js 15, Vitest 2, tsx 4, ESLint 9), so no behavioural migration is expected.

## Why this is a top-tier priority, not a routine `npm audit`

A CVSS table understates these CVEs. The realistic business impact, chained:

### Chain A — SSRF → cloud-metadata service → resource hijack / crypto-mining
`GHSA-c4j6-fc7j-m34r` (CVSS 8.6, SSRF via WebSocket upgrades) lets an attacker make the *server* issue outbound HTTP. On any AWS / GCP / Azure deployment, the first target is the instance metadata service (`169.254.169.254`) — which returns the IAM credentials the workload runs with. From there:

- **Crypto-mining on the org's bill.** Stolen creds → spin up GPU instances (or repurpose existing ones) for Monero. The most common cause of "we got a $50k AWS bill we can't explain" incidents. This is the **Capital One** breach pattern.
- **Lateral movement.** S3 buckets, RDS instances, secrets manager, all reachable from the leaked role.
- **Defence-evasion: the activity looks legitimate** because it originates from the app's own VM.

### Chain B — Cache-poisoned redirects → effective domain hijack
`GHSA-3g8h-86w9-wvmq` + `GHSA-wfc6-r584-vfw7` let an attacker poison a cached response. The next N users on that node fetch attacker-controlled content from `taskboard.dev` — same TLS cert, same URL bar. Used in the wild for:

- **Mass credential phishing** (drop a fake "session expired, please log in" overlay).
- **Drive-by malware** (one-character favicon swap, ship a `<script>` to your customer base).
- **Affiliate-link injection** to siphon revenue.

The origin still says it's you. The customer has no signal that anything's wrong.

### Chain C — Middleware / proxy bypass × 4
`GHSA-492v-c6pp-mqqv`, `GHSA-267c-6grr-h53f`, `GHSA-26hh-7cqf-hhc6`, `GHSA-36qx-fr4f-26g5` (all CVSS 7.5+) let an attacker reach routes the middleware was meant to gate. Anywhere we add **rate-limiting, auth, or geo-blocking in middleware later** (per the rest of this audit's recommendations), the bypass is already there. Fixing the rate-limit code without bumping Next.js is a false sense of security.

### Chain D — Server / Image / Cache DoS
`GHSA-mg66-mrh9-m8jx`, `GHSA-8h8q-6873-q5fj`, `GHSA-h64f-5h5j-jqjh` — server-side resource exhaustion as an attack, not a side-effect. A single attacker can make every other request slow or fail.

### Vitest RCE — dev-side, but supply-chain consequences
`GHSA-9crc-q9x8-hgqq` (CVSS 9.6) is RCE on a developer's machine when they have Vitest running and visit a malicious page. Direct impact: dev box compromised. Real impact: that developer has push credentials, AWS keys, NPM publish tokens. **Compromise one dev → inject malicious code → ship to prod via a normal PR.** This is the `event-stream` / `ua-parser-js` supply-chain pattern.

### Why the patch comes first

Every other finding in this audit is a code change that requires understanding the codebase, writing the diff, reviewing it, deploying it. **This one is four `npm install` lines.** Latency between "we know" and "we're patched" should be minutes, not weeks. Anything else competing for "Tier 1" loses to that asymmetry.

---

## Informational (no current CVE, but dated)

- **bcryptjs 2.4.3** — 2.x line is maintenance-only; 3.0.x is the current line. Not a security blocker.
- **jsonwebtoken 9.0.2**, **zod 3.24.1**, **@prisma/client 6.1.0**, **@tanstack/react-query 5.62.7**, **airtable 0.12.2** — clean against the GitHub Advisory Database at audit time.
