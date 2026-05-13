/**
 * Export worker entrypoint. Run with `npm run worker` (production) or
 * `npm run worker:dev` (with `tsx watch` for autoreload).
 *
 * Graceful shutdown: SIGTERM/SIGINT trigger `worker.close()` which waits
 * for the in-flight batch to settle before exiting. Combined with cursor
 * checkpointing, a clean shutdown loses at most an in-flight batch — which
 * the next pickup replays safely thanks to `performUpsert` idempotency.
 */

import { createExportWorker } from "../src/lib/export-worker";
import { exportQueue } from "../src/lib/export-queue";

async function main() {
  const worker = createExportWorker();
  // eslint-disable-next-line no-console
  console.log("[worker] export worker started");

  const shutdown = async (signal: string) => {
    // eslint-disable-next-line no-console
    console.log(`[worker] received ${signal}, draining…`);
    try {
      await worker.close();
      await exportQueue.close();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("[worker] shutdown error:", err);
    }
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("[worker] fatal:", err);
  process.exit(1);
});
