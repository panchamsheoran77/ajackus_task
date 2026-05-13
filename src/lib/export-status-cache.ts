/**
 * Redis-backed read cache for export status, plus a single-flight guard
 * (`export:active:{projectId}`) that prevents concurrent exports of the
 * same project.
 *
 * Worker is the write-through source; API routes read with DB fallback.
 */

import type { ExportJob } from "@prisma/client";
import { redis } from "./redis";

const ACTIVE_KEY = (projectId: string) => `export:active:${projectId}`;
const STATUS_KEY = (exportId: string) => `export:status:${exportId}`;

const RUNNING_TTL_SECONDS = 300; // 5 min
const TERMINAL_TTL_SECONDS = 3600; // 1 h

const STALLED_THRESHOLD_MS = 2 * 60 * 1000; // 2 min

export type ExportStatusValue =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "stalled";

export type ExportSnapshot = {
  exportId: string;
  projectId: string;
  status: ExportStatusValue;
  totalTasks: number;
  successCount: number;
  failureCount: number;
  attempts: number;
  startedAt: string | null;
  finishedAt: string | null;
  heartbeatAt: string | null;
  updatedAt: string;
  errorsTruncated: boolean;
  errorsSample: unknown[];
};

const MAX_INLINE_ERRORS = 20;

export function buildSnapshot(job: ExportJob): ExportSnapshot {
  const errors = Array.isArray(job.errors) ? (job.errors as unknown[]) : [];
  const sample = errors.slice(0, MAX_INLINE_ERRORS);

  let status: ExportStatusValue = job.status;
  if (
    status === "running" &&
    job.heartbeatAt &&
    Date.now() - job.heartbeatAt.getTime() > STALLED_THRESHOLD_MS
  ) {
    status = "stalled";
  }

  return {
    exportId: job.id,
    projectId: job.projectId,
    status,
    totalTasks: job.totalTasks,
    successCount: job.successCount,
    failureCount: job.failureCount,
    attempts: job.attempts,
    startedAt: job.startedAt?.toISOString() ?? null,
    finishedAt: job.finishedAt?.toISOString() ?? null,
    heartbeatAt: job.heartbeatAt?.toISOString() ?? null,
    updatedAt: new Date().toISOString(),
    errorsTruncated: errors.length > sample.length,
    errorsSample: sample,
  };
}

function isTerminal(s: ExportStatusValue): boolean {
  return s === "succeeded" || s === "failed";
}

/**
 * Single-flight guard. Returns the existing exportId if one is already
 * queued/running for this project, else claims the slot for `candidateId`.
 */
export async function tryClaimActive(
  projectId: string,
  candidateId: string,
): Promise<{ claimed: boolean; activeExportId: string }> {
  // SET NX: only sets if the key doesn't already exist.
  const ok = await redis.set(ACTIVE_KEY(projectId), candidateId, "NX");
  if (ok === "OK") return { claimed: true, activeExportId: candidateId };
  const existing = (await redis.get(ACTIVE_KEY(projectId))) ?? candidateId;
  return { claimed: false, activeExportId: existing };
}

export async function clearActive(projectId: string): Promise<void> {
  await redis.del(ACTIVE_KEY(projectId));
}

export async function setStatus(snapshot: ExportSnapshot): Promise<void> {
  const ttl = isTerminal(snapshot.status)
    ? TERMINAL_TTL_SECONDS
    : RUNNING_TTL_SECONDS;
  await redis.set(STATUS_KEY(snapshot.exportId), JSON.stringify(snapshot), "EX", ttl);
}

export async function getStatus(exportId: string): Promise<ExportSnapshot | null> {
  const raw = await redis.get(STATUS_KEY(exportId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ExportSnapshot;
  } catch {
    return null;
  }
}
