// @vitest-environment node
import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";

vi.mock("@/lib/prisma", () => ({
  prisma: {
    user: { findUnique: vi.fn() },
    membership: { findUnique: vi.fn() },
    exportJob: {
      create: vi.fn(),
      findUnique: vi.fn(),
      findMany: vi.fn(),
      delete: vi.fn(),
    },
  },
}));

vi.mock("@/lib/redis", () => {
  const store = new Map<string, string>();
  const redis = {
    set: vi.fn(async (key: string, value: string, ...rest: unknown[]) => {
      if (rest.includes("NX") && store.has(key)) return null;
      store.set(key, value);
      return "OK";
    }),
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    del: vi.fn(async (key: string) => {
      const had = store.has(key);
      store.delete(key);
      return had ? 1 : 0;
    }),
    __store: store,
  };
  return { redis, redisForBull: redis };
});

vi.mock("@/lib/export-queue", () => ({
  enqueueExport: vi.fn(async (id: string) => id),
}));

import { POST, GET as GETList } from "@/app/api/projects/[id]/exports/route";
import { GET as GETStatus } from "@/app/api/projects/[id]/exports/[exportId]/route";
import { prisma } from "@/lib/prisma";
import { redis } from "@/lib/redis";
import { enqueueExport } from "@/lib/export-queue";
import {
  mintToken,
  newGetRequest,
  newPostRequest,
} from "@/tests/helpers/http";

const USER = { id: "u_1", email: "u@x.dev", name: "U" };
const PROJECT_ID = "p_1";
const EXPORT_ID = "ej_1";

function asMock<T extends (...a: never[]) => unknown>(fn: T): Mock {
  return fn as unknown as Mock;
}

function paramsForProject(projectId: string) {
  return { params: Promise.resolve({ id: projectId }) };
}
function paramsForExport(projectId: string, exportId: string) {
  return { params: Promise.resolve({ id: projectId, exportId }) };
}

function jobRow(over: Partial<Record<string, unknown>> = {}) {
  return {
    id: EXPORT_ID,
    projectId: PROJECT_ID,
    triggeredById: USER.id,
    status: "queued",
    totalTasks: 0,
    successCount: 0,
    failureCount: 0,
    errors: null,
    attempts: 0,
    lastProcessedTaskId: null,
    heartbeatAt: null,
    bullJobId: null,
    startedAt: null,
    finishedAt: null,
    createdAt: new Date("2026-05-13T10:00:00Z"),
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  asMock(prisma.user.findUnique).mockResolvedValue(USER);
  asMock(prisma.membership.findUnique).mockResolvedValue({ role: "member" });
  asMock(prisma.exportJob.create).mockResolvedValue(jobRow());
  asMock(prisma.exportJob.findUnique).mockResolvedValue(jobRow());
  asMock(prisma.exportJob.findMany).mockResolvedValue([]);
  asMock(prisma.exportJob.delete).mockResolvedValue(jobRow());
  (redis as unknown as { __store: Map<string, string> }).__store.clear();
});

// =====================================================================
// POST /api/projects/:id/exports — auth & role
// =====================================================================
describe("POST /api/projects/:id/exports — auth", () => {
  it("401 without bearer", async () => {
    const req = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
    );
    const res = await POST(req, paramsForProject(PROJECT_ID));
    expect(res.status).toBe(401);
    expect(prisma.exportJob.create).not.toHaveBeenCalled();
  });

  it("403 when not a member of the project", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue(null);
    const req = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
      mintToken(USER.id, USER.email),
    );
    const res = await POST(req, paramsForProject(PROJECT_ID));
    expect(res.status).toBe(403);
    expect(prisma.exportJob.create).not.toHaveBeenCalled();
  });

  it("403 when role is viewer", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue({ role: "viewer" });
    const req = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
      mintToken(USER.id, USER.email),
    );
    const res = await POST(req, paramsForProject(PROJECT_ID));
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("viewers cannot trigger exports");
  });

  it.each(["admin", "member"] as const)(
    "allows role=%s to trigger",
    async (role) => {
      asMock(prisma.membership.findUnique).mockResolvedValue({ role });
      const req = newPostRequest(
        `http://localhost/api/projects/${PROJECT_ID}/exports`,
        {},
        mintToken(USER.id, USER.email),
      );
      const res = await POST(req, paramsForProject(PROJECT_ID));
      expect(res.status).toBe(202);
      expect(prisma.exportJob.create).toHaveBeenCalledTimes(1);
      expect(enqueueExport).toHaveBeenCalledWith(EXPORT_ID);
    },
  );
});

// =====================================================================
// Single-flight guard
// =====================================================================
describe("POST /api/projects/:id/exports — single-flight", () => {
  it("returns the existing active export when one is already running", async () => {
    // First call claims.
    const req1 = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
      mintToken(USER.id, USER.email),
    );
    const res1 = await POST(req1, paramsForProject(PROJECT_ID));
    expect(res1.status).toBe(202);
    expect(enqueueExport).toHaveBeenCalledTimes(1);

    // Second concurrent call must NOT enqueue a second job.
    const req2 = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
      mintToken(USER.id, USER.email),
    );
    const res2 = await POST(req2, paramsForProject(PROJECT_ID));
    expect(res2.status).toBe(200);
    const body2 = await res2.json();
    expect(body2.alreadyRunning).toBe(true);
    expect(body2.snapshot.exportId).toBe(EXPORT_ID);
    expect(enqueueExport).toHaveBeenCalledTimes(1);
  });

  it("releases the active claim if enqueue fails", async () => {
    asMock(enqueueExport).mockRejectedValueOnce(new Error("redis down"));
    const req = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
      mintToken(USER.id, USER.email),
    );
    const res = await POST(req, paramsForProject(PROJECT_ID));
    expect(res.status).toBe(503);
    // Claim was released → another POST can succeed.
    asMock(enqueueExport).mockResolvedValueOnce(EXPORT_ID);
    const req2 = newPostRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      {},
      mintToken(USER.id, USER.email),
    );
    const res2 = await POST(req2, paramsForProject(PROJECT_ID));
    expect(res2.status).toBe(202);
  });
});

// =====================================================================
// GET status (Redis-first)
// =====================================================================
describe("GET /api/projects/:id/exports/:exportId — Redis cache", () => {
  it("requires membership", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue(null);
    const req = newGetRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports/${EXPORT_ID}`,
      mintToken(USER.id, USER.email),
    );
    const res = await GETStatus(req, paramsForExport(PROJECT_ID, EXPORT_ID));
    expect(res.status).toBe(403);
  });

  it("returns cached snapshot without touching the DB after first read", async () => {
    // First read: cache miss → DB once, then backfill.
    const reqA = newGetRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports/${EXPORT_ID}`,
      mintToken(USER.id, USER.email),
    );
    const resA = await GETStatus(reqA, paramsForExport(PROJECT_ID, EXPORT_ID));
    expect(resA.status).toBe(200);
    const bodyA = await resA.json();
    expect(bodyA.cached).toBe(false);
    expect(prisma.exportJob.findUnique).toHaveBeenCalledTimes(1);

    // Second read: cached.
    asMock(prisma.exportJob.findUnique).mockClear();
    const reqB = newGetRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports/${EXPORT_ID}`,
      mintToken(USER.id, USER.email),
    );
    const resB = await GETStatus(reqB, paramsForExport(PROJECT_ID, EXPORT_ID));
    expect(resB.status).toBe(200);
    const bodyB = await resB.json();
    expect(bodyB.cached).toBe(true);
    expect(prisma.exportJob.findUnique).not.toHaveBeenCalled();
  });

  it("404 when the export does not belong to the project", async () => {
    asMock(prisma.exportJob.findUnique).mockResolvedValue(
      jobRow({ projectId: "p_other" }),
    );
    const req = newGetRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports/${EXPORT_ID}`,
      mintToken(USER.id, USER.email),
    );
    const res = await GETStatus(req, paramsForExport(PROJECT_ID, EXPORT_ID));
    expect(res.status).toBe(404);
  });
});

// =====================================================================
// GET list
// =====================================================================
describe("GET /api/projects/:id/exports — list", () => {
  it("returns recent exports for the project as snapshots", async () => {
    asMock(prisma.exportJob.findMany).mockResolvedValue([
      jobRow({ id: "ej_3", status: "succeeded" }),
      jobRow({ id: "ej_2", status: "failed" }),
    ]);
    const req = newGetRequest(
      `http://localhost/api/projects/${PROJECT_ID}/exports`,
      mintToken(USER.id, USER.email),
    );
    const res = await GETList(req, paramsForProject(PROJECT_ID));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.exports).toHaveLength(2);
    expect(body.exports[0].status).toBe("succeeded");
  });
});
