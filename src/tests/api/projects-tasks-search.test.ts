// @vitest-environment node
import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";

// IMPORTANT: vi.mock is hoisted above the imports below. The route under test
// imports `prisma` from `@/lib/prisma`; this mock replaces that module entirely
// so no real database connection is made.
vi.mock("@/lib/prisma", () => ({
  prisma: {
    user: { findUnique: vi.fn() },
    membership: { findUnique: vi.fn() },
    task: { findMany: vi.fn() },
    // Tracked so we can ASSERT the fix never falls back to raw SQL.
    $queryRawUnsafe: vi.fn(),
    $executeRawUnsafe: vi.fn(),
    $queryRaw: vi.fn(),
  },
}));

import { GET } from "@/app/api/projects/[id]/tasks/route";
import { prisma } from "@/lib/prisma";
import { mintToken, newGetRequest, paramsFor } from "@/tests/helpers/http";
import { SQLI_PAYLOADS } from "@/tests/helpers/sqli-payloads";

const DEV = { id: "u_dev", email: "dev@example.com", name: "Dev" };
const KAVYA = { id: "u_kavya", email: "kavya@example.com", name: "Kavya" };
const Q3_ID = "p_q3";
const ONB_ID = "p_onb";

function asMock<T extends (...args: never[]) => unknown>(fn: T): Mock {
  return fn as unknown as Mock;
}

beforeEach(() => {
  vi.clearAllMocks();
  // Sane defaults: caller is dev (viewer on Q3), membership found, no tasks.
  // Each test overrides what it cares about.
  asMock(prisma.user.findUnique).mockResolvedValue(DEV);
  asMock(prisma.membership.findUnique).mockResolvedValue({ role: "viewer" });
  asMock(prisma.task.findMany).mockResolvedValue([]);
});

async function callGet(opts: {
  user?: { id: string; email: string };
  projectId?: string;
  q?: string;
  bearer?: string | null; // null → no header; undefined → mint from `user`
}) {
  const projectId = opts.projectId ?? Q3_ID;
  const user = opts.user ?? DEV;
  const bearer =
    opts.bearer === null
      ? undefined
      : (opts.bearer ?? mintToken(user.id, user.email));
  const search = opts.q !== undefined ? `?q=${encodeURIComponent(opts.q)}` : "";
  const req = newGetRequest(
    `http://localhost/api/projects/${projectId}/tasks${search}`,
    bearer,
  );
  return await GET(req, paramsFor(projectId));
}

// =====================================================================
// §4.1 — Security regressions (the SQLi fix's contract)
// =====================================================================
describe("GET /api/projects/:id/tasks?q= — SQLi regressions", () => {
  it("never calls $queryRawUnsafe / $executeRawUnsafe — for ANY q", async () => {
    for (const payload of SQLI_PAYLOADS) {
      asMock(prisma.task.findMany).mockResolvedValue([]);
      const res = await callGet({ q: payload });
      expect(res.status).toBe(200);
    }
    expect(prisma.$queryRawUnsafe).not.toHaveBeenCalled();
    expect(prisma.$executeRawUnsafe).not.toHaveBeenCalled();
  });

  it("[OR 1=1] is passed to findMany as a LITERAL `contains` filter, not SQL", async () => {
    const payload = "%') OR 1=1 -- ";
    await callGet({ q: payload });

    expect(prisma.task.findMany).toHaveBeenCalledTimes(1);
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    // The raw payload survives intact, slotted into a Prisma `contains` —
    // it is a bound parameter, not part of the SQL string.
    expect(arg.where.OR).toEqual([
      { title:       { contains: payload, mode: "insensitive" } },
      { description: { contains: payload, mode: "insensitive" } },
    ]);
  });

  it("[UNION SELECT FROM users] is passed as a literal — never returns a bcrypt hash", async () => {
    const payload = `%') UNION SELECT id,email,name,password_hash,NULL::"TaskStatus",NULL,'',0,created_at,updated_at FROM users -- `;
    // Even if the mock were tricked into returning bcrypt-shaped rows, the route
    // would just pass them through — what matters is the SQL never runs the UNION.
    asMock(prisma.task.findMany).mockResolvedValue([]);

    const res = await callGet({ q: payload });
    const raw = JSON.stringify(await res.json());
    expect(raw).not.toMatch(/\$2[ayb]\$\d+\$[A-Za-z0-9./]{53}/);

    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where.OR[0].title.contains).toBe(payload);
  });

  it("[DROP TABLE] is passed as a literal — no raw-SQL fall-through", async () => {
    const payload = "'; DROP TABLE tasks; -- ";
    await callGet({ q: payload });
    expect(prisma.$queryRawUnsafe).not.toHaveBeenCalled();
    expect(prisma.$executeRawUnsafe).not.toHaveBeenCalled();
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where.OR[0].title.contains).toBe(payload);
  });

  it("findMany's WHERE always pins `projectId` to the URL's :id — cross-tenant invariant", async () => {
    for (const payload of SQLI_PAYLOADS) {
      asMock(prisma.task.findMany).mockClear();
      await callGet({ q: payload, projectId: Q3_ID });
      const arg = asMock(prisma.task.findMany).mock.calls[0][0];
      expect(arg.where.projectId).toBe(Q3_ID);
    }
  });
});

// =====================================================================
// §4.2 — Functional: search still works
// =====================================================================
describe("GET /api/projects/:id/tasks?q= — search behaviour", () => {
  it("passes the search term as `contains` with `mode: 'insensitive'`", async () => {
    await callGet({ q: "launch" });
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where.OR[0].title.contains).toBe("launch");
    expect(arg.where.OR[0].title.mode).toBe("insensitive");
    expect(arg.where.OR[1].description.contains).toBe("launch");
    expect(arg.where.OR[1].description.mode).toBe("insensitive");
  });

  it("returns whatever the data layer returns, in the response `tasks` field", async () => {
    const rows = [
      {
        id: "t1",
        projectId: Q3_ID,
        title: "Finalize launch date with marketing",
        description: "Detail for: …",
        status: "done",
        assigneeId: null,
        createdById: "u_meera",
        position: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
        assignee: null,
      },
    ];
    asMock(prisma.task.findMany).mockResolvedValue(rows);
    const res = await callGet({ q: "launch" });
    const body = await res.json();
    expect(body.tasks).toHaveLength(1);
    expect(body.tasks[0].title).toBe("Finalize launch date with marketing");
  });

  it("orders results by `position asc`", async () => {
    await callGet({ q: "anything" });
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.orderBy).toEqual({ position: "asc" });
  });

  it("includes the `assignee` join with the safe field projection", async () => {
    await callGet({ q: "anything" });
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.include.assignee.select).toEqual({
      id: true,
      name: true,
      email: true,
    });
  });

  it("response shape matches the non-q branch (same include shape)", async () => {
    await callGet({ q: "launch" });
    const withQArg = asMock(prisma.task.findMany).mock.calls[0][0];
    asMock(prisma.task.findMany).mockClear();
    await callGet({}); // no q
    const noQArg = asMock(prisma.task.findMany).mock.calls[0][0];
    // The include shape must be identical so callers receive the same task structure.
    expect(withQArg.include).toEqual(noQArg.include);
  });
});

// =====================================================================
// §4.3 — Authorization gate intact
// =====================================================================
describe("GET /api/projects/:id/tasks?q= — authorization", () => {
  it("returns 401 without an Authorization header", async () => {
    const res = await callGet({ q: "launch", bearer: null });
    expect(res.status).toBe(401);
    expect(prisma.task.findMany).not.toHaveBeenCalled();
  });

  it("returns 401 for a malformed token", async () => {
    const res = await callGet({ q: "launch", bearer: "not.a.real.token" });
    expect(res.status).toBe(401);
    expect(prisma.task.findMany).not.toHaveBeenCalled();
  });

  it("returns 401 if the JWT references a user that no longer exists", async () => {
    asMock(prisma.user.findUnique).mockResolvedValue(null);
    const res = await callGet({ q: "launch" });
    expect(res.status).toBe(401);
    expect(prisma.task.findMany).not.toHaveBeenCalled();
  });

  it("returns 403 when caller is not a member of the project", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue(null);
    const res = await callGet({ q: "launch", projectId: ONB_ID });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("you are not a member of this project");
    expect(prisma.task.findMany).not.toHaveBeenCalled();
  });

  it.each(["viewer", "member", "admin"] as const)(
    "allows role=%s to search (read access)",
    async (role) => {
      asMock(prisma.membership.findUnique).mockResolvedValue({ role });
      const res = await callGet({ user: KAVYA, q: "launch" });
      expect(res.status).toBe(200);
    },
  );
});

// =====================================================================
// §4.4 — Edge cases
// =====================================================================
describe("GET /api/projects/:id/tasks?q= — edge cases", () => {
  it("missing q falls through to the non-q branch (no OR filter)", async () => {
    await callGet({});
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where).toEqual({ projectId: Q3_ID });
    expect(arg.where.OR).toBeUndefined();
  });

  it("empty q ('') falls through to the non-q branch", async () => {
    await callGet({ q: "" });
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where.OR).toBeUndefined();
    // Non-q branch sorts by status then position.
    expect(arg.orderBy).toEqual([{ status: "asc" }, { position: "asc" }]);
  });

  it("very long q (5000 chars) is forwarded intact, no truncation, returns 200", async () => {
    const longQ = "x".repeat(5000);
    const res = await callGet({ q: longQ });
    expect(res.status).toBe(200);
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where.OR[0].title.contains).toBe(longQ);
  });

  it("LIKE metacharacters (%, _) flow through as literal `contains` values", async () => {
    // Prisma escapes %, _ at the driver layer when using `contains`. The route
    // is responsible only for passing the user's q verbatim into `contains`.
    await callGet({ q: "%" });
    const argPct = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(argPct.where.OR[0].title.contains).toBe("%");

    asMock(prisma.task.findMany).mockClear();
    await callGet({ q: "_" });
    const argUnd = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(argUnd.where.OR[0].title.contains).toBe("_");
  });

  it("admin search results stay scoped to the URL's :id (projectId in WHERE)", async () => {
    // The handler must never widen the projectId filter regardless of role.
    asMock(prisma.membership.findUnique).mockResolvedValue({ role: "admin" });
    await callGet({ q: "Detail for", projectId: Q3_ID });
    const arg = asMock(prisma.task.findMany).mock.calls[0][0];
    expect(arg.where.projectId).toBe(Q3_ID);
  });
});
