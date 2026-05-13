/**
 * Known SQL-injection attack patterns. Used in security regression tests to
 * verify that none of them leaks data through the search endpoint.
 *
 * The contract these tests assert against:
 *   For ANY payload in this list, GET /api/projects/:id/tasks?q=<payload>
 *   must (a) return HTTP 200 with a tasks array, and (b) every task in that
 *   array has projectId === :id (i.e. no cross-tenant leakage).
 *
 * Any new payload class found in the wild should be added here.
 */
export const SQLI_PAYLOADS: readonly string[] = [
  // Boolean-based auth bypass — the original PoC payload
  "%') OR 1=1 -- ",
  "%' OR 1=1 -- ",
  "' OR '1'='1",
  "' OR 1=1 --",
  "') OR ('1'='1",

  // UNION-based exfiltration variants
  `%') UNION SELECT id,email,name,password_hash,NULL::"TaskStatus",NULL,'',0,created_at,updated_at FROM users -- `,
  "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --",

  // Stacked-statement / DDL injection
  "'; DROP TABLE tasks; -- ",
  "'; TRUNCATE users; -- ",

  // Block-comment terminator instead of `--`
  "' OR 1=1 /*",

  // Time-based blind variants
  "1' AND SLEEP(5) -- ",
  "' OR pg_sleep(5) -- ",

  // Classic auth-bypass strings
  "admin'--",
] as const;
