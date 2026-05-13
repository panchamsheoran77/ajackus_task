/**
 * BullMQ processor for export jobs.
 *
 * Per-batch behaviour:
 *   1. Read up to PAGE_SIZE tasks from Postgres, cursor-paginated.
 *   2. Chunk into batches of 10, upsert into Airtable via `upsertBatch`.
 *   3. Checkpoint cursor + counts + errors to the ExportJob row.
 *   4. Write the status snapshot to Redis (write-through cache).
 *
 * Crash recovery: cursor is persisted before moving on, so a restarted job
 * resumes from `lastProcessedTaskId`. Replayed batches are no-ops in
 * Airtable because `performUpsert` matches on `TaskBoardId`.
 */

import { UnrecoverableError, Worker, type Job } from "bullmq";
import type { Task, User } from "@prisma/client";
import { prisma } from "./prisma";
import { redisForBull } from "./redis";
import { EXPORT_QUEUE_NAME, type ExportJobData } from "./export-queue";
import {
  upsertBatch,
  UnrecoverableExportError,
  type TaskFields,
  type RecordError,
} from "./airtable";
import {
  buildSnapshot,
  clearActive,
  setStatus,
} from "./export-status-cache";

const PAGE_SIZE = 100;
const BATCH_SIZE = 10;

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function toFields(task: Task & { assignee: User | null }): TaskFields {
  return {
    TaskBoardId: task.id,
    Title: task.title,
    Description: task.description,
    Status: task.status,
    Assignee: task.assignee?.name ?? null,
    CreatedAt: task.createdAt.toISOString(),
    UpdatedAt: task.updatedAt.toISOString(),
  };
}

async function publishSnapshot(exportJobId: string): Promise<void> {
  const job = await prisma.exportJob.findUnique({ where: { id: exportJobId } });
  if (!job) return;
  await setStatus(buildSnapshot(job));
}

async function processExport(job: Job<ExportJobData>): Promise<void> {
  const { exportJobId } = job.data;

  // 1. Atomic claim. Only transition queued/running → running; if the row is
  //    already terminal, somebody else finished it (e.g. a duplicate enqueue).
  const claimed = await prisma.exportJob.updateMany({
    where: { id: exportJobId, status: { in: ["queued", "running"] } },
    data: {
      status: "running",
      attempts: { increment: 1 },
      heartbeatAt: new Date(),
      bullJobId: job.id ?? null,
    },
  });
  if (claimed.count === 0) return;

  // Set startedAt only on the first transition into running.
  await prisma.exportJob.updateMany({
    where: { id: exportJobId, startedAt: null },
    data: { startedAt: new Date() },
  });

  const exportJob = await prisma.exportJob.findUnique({
    where: { id: exportJobId },
  });
  if (!exportJob) throw new UnrecoverableError(`export job ${exportJobId} not found`);

  // 2. Determine total once.
  if (exportJob.totalTasks === 0) {
    const total = await prisma.task.count({ where: { projectId: exportJob.projectId } });
    await prisma.exportJob.update({
      where: { id: exportJobId },
      data: { totalTasks: total },
    });
    exportJob.totalTasks = total;
  }

  await publishSnapshot(exportJobId);

  // 3. Cursor-paginate from where we left off.
  let cursor: string | undefined = exportJob.lastProcessedTaskId ?? undefined;
  let totalProcessed = exportJob.successCount + exportJob.failureCount;

  try {
    while (true) {
      const page = await prisma.task.findMany({
        where: { projectId: exportJob.projectId },
        include: { assignee: true },
        orderBy: { id: "asc" },
        take: PAGE_SIZE,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
      });
      if (page.length === 0) break;

      for (const batch of chunk(page, BATCH_SIZE)) {
        const result = await upsertBatch(
          batch.map((t) => ({ fields: toFields(t) })),
        );

        const lastId = batch[batch.length - 1].id;
        await checkpoint(exportJobId, lastId, result.successCount, result.failures);
        totalProcessed += batch.length;

        await publishSnapshot(exportJobId);
        await job.updateProgress({
          processed: totalProcessed,
          total: exportJob.totalTasks,
        });
      }
      cursor = page[page.length - 1].id;
    }
  } catch (err) {
    if (err instanceof UnrecoverableExportError) {
      // Permanent error like 401/403/404 — mark failed, do not retry.
      await prisma.exportJob.update({
        where: { id: exportJobId },
        data: {
          status: "failed",
          finishedAt: new Date(),
          errors: appendError(exportJob.errors, {
            taskBoardId: "_export_",
            message: err.message,
            statusCode: err.statusCode,
          }),
        },
      });
      await clearActive(exportJob.projectId);
      await publishSnapshot(exportJobId);
      throw new UnrecoverableError(err.message);
    }
    throw err; // transient/unknown — let BullMQ retry the job
  }

  // 4. Terminal — succeeded.
  await prisma.exportJob.update({
    where: { id: exportJobId },
    data: { status: "succeeded", finishedAt: new Date() },
  });
  await clearActive(exportJob.projectId);
  await publishSnapshot(exportJobId);
}

function appendError(existing: unknown, entry: RecordError): RecordError[] {
  const arr = Array.isArray(existing) ? (existing as RecordError[]) : [];
  return [...arr, entry];
}

async function checkpoint(
  exportJobId: string,
  lastProcessedTaskId: string,
  successCount: number,
  failures: RecordError[],
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    const job = await tx.exportJob.findUnique({ where: { id: exportJobId } });
    if (!job) return;
    const errors = Array.isArray(job.errors) ? (job.errors as RecordError[]) : [];
    await tx.exportJob.update({
      where: { id: exportJobId },
      data: {
        lastProcessedTaskId,
        successCount: { increment: successCount },
        failureCount: { increment: failures.length },
        errors: failures.length > 0 ? [...errors, ...failures] : (job.errors ?? undefined),
        heartbeatAt: new Date(),
      },
    });
  });
}

export function createExportWorker(): Worker<ExportJobData> {
  const worker = new Worker<ExportJobData>(EXPORT_QUEUE_NAME, processExport, {
    connection: redisForBull,
    concurrency: 2,
    lockDuration: 30_000,
    lockRenewTime: 15_000,
    stalledInterval: 30_000,
  });

  worker.on("failed", (job, err) => {
    // eslint-disable-next-line no-console
    console.error(`[export-worker] job ${job?.id} failed:`, err.message);
  });
  worker.on("error", (err) => {
    // eslint-disable-next-line no-console
    console.error("[export-worker] error:", err);
  });

  return worker;
}

// Exposed for tests.
export const __internals = { processExport, checkpoint, toFields };
