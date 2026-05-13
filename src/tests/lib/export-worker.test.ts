// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AirtableMockClient } from "@/lib/airtable-mock";

/**
 * These tests exercise the worker's core loop end-to-end using the
 * existing in-memory Airtable mock (record map keyed by id). The Prisma
 * client is replaced with an in-memory fake that supports cursor
 * pagination and atomic claim transitions. Redis is stubbed to no-op
 * the status writes so we can focus on idempotency and resume.
 */

// ---------- in-memory prisma fake ----------
type Task = {
  id: string;
  projectId: string;
  title: string;
  description: string | null;
  status: "todo" | "in_progress" | "review" | "done";
  createdAt: Date;
  updatedAt: Date;
  assignee: null;
};
type ExportJob = {
  id: string;
  projectId: string;
  triggeredById: string;
  status: "queued" | "running" | "succeeded" | "failed";
  totalTasks: number;
  successCount: number;
  failureCount: number;
  errors: unknown;
  attempts: number;
  lastProcessedTaskId: string | null;
  heartbeatAt: Date | null;
  bullJobId: string | null;
  startedAt: Date | null;
  finishedAt: Date | null;
  createdAt: Date;
};

const tasks: Task[] = [];
const jobs = new Map<string, ExportJob>();

function makeTask(i: number, projectId: string): Task {
  return {
    id: `task_${String(i).padStart(4, "0")}`,
    projectId,
    title: `task ${i}`,
    description: null,
    status: "todo",
    createdAt: new Date("2026-05-13T10:00:00Z"),
    updatedAt: new Date("2026-05-13T10:00:00Z"),
    assignee: null,
  };
}

function seedTasks(projectId: string, n: number) {
  tasks.length = 0;
  for (let i = 0; i < n; i++) tasks.push(makeTask(i, projectId));
}

function makeJob(id: string, projectId: string): ExportJob {
  const j: ExportJob = {
    id,
    projectId,
    triggeredById: "u_1",
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
  };
  jobs.set(id, j);
  return j;
}

// Minimal prisma fake covering only the calls the worker makes.
const prismaFake = {
  task: {
    count: vi.fn(
      async ({ where }: { where: { projectId: string } }) =>
        tasks.filter((t) => t.projectId === where.projectId).length,
    ),
    findMany: vi.fn(
      async (args: {
        where: { projectId: string };
        take: number;
        cursor?: { id: string };
        skip?: number;
      }) => {
        const list = tasks
          .filter((t) => t.projectId === args.where.projectId)
          .sort((a, b) => a.id.localeCompare(b.id));
        let startIdx = 0;
        if (args.cursor) {
          const i = list.findIndex((t) => t.id === args.cursor!.id);
          startIdx = i + (args.skip ?? 0);
        }
        return list.slice(startIdx, startIdx + args.take);
      },
    ),
  },
  exportJob: {
    updateMany: vi.fn(async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
      const job = jobs.get(args.where.id as string);
      if (!job) return { count: 0 };
      // Check `status: { in: [...] }`
      const statusFilter = args.where.status as { in?: string[] } | undefined;
      if (statusFilter?.in && !statusFilter.in.includes(job.status)) {
        return { count: 0 };
      }
      // Check `startedAt: null`
      if (args.where.startedAt === null && job.startedAt !== null) {
        return { count: 0 };
      }
      Object.entries(args.data).forEach(([k, v]) => {
        if (
          typeof v === "object" &&
          v !== null &&
          "increment" in (v as object)
        ) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (job as any)[k] = ((job as any)[k] ?? 0) + (v as { increment: number }).increment;
        } else {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (job as any)[k] = v;
        }
      });
      return { count: 1 };
    }),
    findUnique: vi.fn(
      async (args: { where: { id: string } }) => jobs.get(args.where.id) ?? null,
    ),
    update: vi.fn(async (args: { where: { id: string }; data: Record<string, unknown> }) => {
      const job = jobs.get(args.where.id);
      if (!job) throw new Error(`no job ${args.where.id}`);
      Object.entries(args.data).forEach(([k, v]) => {
        if (
          typeof v === "object" &&
          v !== null &&
          "increment" in (v as object)
        ) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (job as any)[k] = ((job as any)[k] ?? 0) + (v as { increment: number }).increment;
        } else {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (job as any)[k] = v;
        }
      });
      return job;
    }),
  },
  $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(prismaFake)),
};

vi.mock("@/lib/prisma", () => ({ prisma: prismaFake }));

vi.mock("@/lib/redis", () => ({
  redis: {
    set: vi.fn(async () => "OK"),
    get: vi.fn(async () => null),
    del: vi.fn(async () => 1),
  },
  redisForBull: {},
}));

vi.mock("bullmq", () => ({
  UnrecoverableError: class UnrecoverableError extends Error {},
  Worker: class {},
  Queue: class {
    add = vi.fn(async () => ({ id: "stub" }));
    close = vi.fn(async () => {});
  },
}));

vi.mock("@/lib/export-queue", () => ({
  EXPORT_QUEUE_NAME: "exports",
  exportQueue: { add: vi.fn(), close: vi.fn() },
  enqueueExport: vi.fn(async (id: string) => id),
}));

// Patch the airtable module to route through our mock client.
const airtableMock = new AirtableMockClient();
vi.mock("@/lib/airtable", async () => {
  const actual = await vi.importActual<typeof import("@/lib/airtable")>(
    "@/lib/airtable",
  );
  return {
    ...actual,
    upsertBatch: vi.fn(
      async (records: { fields: { TaskBoardId: string } }[]) => {
        for (const r of records) {
          await airtableMock.create({
            id: r.fields.TaskBoardId,
            fields: r.fields as unknown as Record<string, unknown>,
          });
        }
        return { successCount: records.length, failures: [] };
      },
    ),
  };
});

// Now import the worker (after mocks are set up).
const { __internals } = await import("@/lib/export-worker");
const { processExport } = __internals;

function makeBullJob(exportJobId: string) {
  return {
    id: `bull_${exportJobId}`,
    data: { exportJobId },
    updateProgress: vi.fn(async () => {}),
  };
}

const PROJECT_ID = "p_1";

beforeEach(() => {
  jobs.clear();
  tasks.length = 0;
  airtableMock.__reset();
  vi.clearAllMocks();
});

describe("processExport — happy path", () => {
  it("exports all tasks of a project, marks succeeded", async () => {
    seedTasks(PROJECT_ID, 47);
    const job = makeJob("ej_happy", PROJECT_ID);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await processExport(makeBullJob(job.id) as any);

    const updated = jobs.get("ej_happy")!;
    expect(updated.status).toBe("succeeded");
    expect(updated.totalTasks).toBe(47);
    expect(updated.successCount).toBe(47);
    expect(updated.failureCount).toBe(0);
    expect(airtableMock.__getRecordCount()).toBe(47);
  });
});

describe("processExport — idempotency", () => {
  it("running the export twice produces no duplicates in Airtable", async () => {
    seedTasks(PROJECT_ID, 25);
    const job = makeJob("ej_idem", PROJECT_ID);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await processExport(makeBullJob(job.id) as any);
    expect(airtableMock.__getRecordCount()).toBe(25);

    // Reset job back to queued to simulate a re-run (e.g. user re-triggers).
    const j = jobs.get("ej_idem")!;
    j.status = "queued";
    j.lastProcessedTaskId = null;
    j.successCount = 0;
    j.failureCount = 0;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await processExport(makeBullJob(job.id) as any);
    // Still 25 records — the mock's `create` with explicit `id` upserts
    // exactly as Airtable's performUpsert would.
    expect(airtableMock.__getRecordCount()).toBe(25);
  });
});

describe("processExport — resume after crash", () => {
  it("resumes from lastProcessedTaskId and replayed batch is idempotent", async () => {
    seedTasks(PROJECT_ID, 30);
    const job = makeJob("ej_resume", PROJECT_ID);

    // Pre-populate Airtable with the first 17 tasks as if a previous run
    // had processed batches up to that point but crashed before checkpointing
    // the final batch.
    for (let i = 0; i < 17; i++) {
      await airtableMock.create({
        id: tasks[i].id,
        fields: { TaskBoardId: tasks[i].id } as unknown as Record<string, unknown>,
      });
    }

    // Mark the job as if it had checkpointed batch #1 (10 tasks).
    const j = jobs.get("ej_resume")!;
    j.status = "running";
    j.lastProcessedTaskId = tasks[9].id;
    j.successCount = 10;
    j.totalTasks = 30;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await processExport(makeBullJob(job.id) as any);

    const updated = jobs.get("ej_resume")!;
    expect(updated.status).toBe("succeeded");
    expect(airtableMock.__getRecordCount()).toBe(30);
    // Worker resumed from task_0009; only tasks 10..29 were re-pushed.
    // The 7 already-in-Airtable rows (10..16) were upserted in place.
    expect(updated.successCount).toBe(10 + 20);
  });
});

describe("processExport — atomic claim", () => {
  it("does not re-run an already terminal job", async () => {
    seedTasks(PROJECT_ID, 5);
    const job = makeJob("ej_done", PROJECT_ID);
    const j = jobs.get("ej_done")!;
    j.status = "succeeded";
    j.finishedAt = new Date();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await processExport(makeBullJob(job.id) as any);

    // Worker should have bailed out at the claim step.
    expect(airtableMock.__getRecordCount()).toBe(0);
    expect(j.status).toBe("succeeded");
  });
});
