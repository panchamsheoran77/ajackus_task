import { Queue } from "bullmq";
import { redisForBull } from "./redis";

export const EXPORT_QUEUE_NAME = "exports";

export type ExportJobData = {
  exportJobId: string;
};

declare global {
  // eslint-disable-next-line no-var
  var __exportQueue: Queue<ExportJobData> | undefined;
}

export const exportQueue: Queue<ExportJobData> =
  globalThis.__exportQueue ??
  new Queue<ExportJobData>(EXPORT_QUEUE_NAME, {
    connection: redisForBull,
    defaultJobOptions: {
      attempts: 5,
      backoff: { type: "exponential", delay: 2000 },
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 500 },
    },
  });

if (process.env.NODE_ENV !== "production") globalThis.__exportQueue = exportQueue;

export async function enqueueExport(exportJobId: string): Promise<string> {
  const job = await exportQueue.add(
    "export",
    { exportJobId },
    { jobId: exportJobId },
  );
  return job.id ?? exportJobId;
}
