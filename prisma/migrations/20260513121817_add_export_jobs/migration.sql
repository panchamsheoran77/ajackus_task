-- CreateEnum
CREATE TYPE "ExportStatus" AS ENUM ('queued', 'running', 'succeeded', 'failed');

-- CreateTable
CREATE TABLE "export_jobs" (
    "id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "triggered_by_id" TEXT NOT NULL,
    "status" "ExportStatus" NOT NULL DEFAULT 'queued',
    "total_tasks" INTEGER NOT NULL DEFAULT 0,
    "success_count" INTEGER NOT NULL DEFAULT 0,
    "failure_count" INTEGER NOT NULL DEFAULT 0,
    "errors" JSONB,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_processed_task_id" TEXT,
    "heartbeat_at" TIMESTAMP(3),
    "bull_job_id" TEXT,
    "started_at" TIMESTAMP(3),
    "finished_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "export_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "export_jobs_project_id_created_at_idx" ON "export_jobs"("project_id", "created_at");

-- AddForeignKey
ALTER TABLE "export_jobs" ADD CONSTRAINT "export_jobs_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "export_jobs" ADD CONSTRAINT "export_jobs_triggered_by_id_fkey" FOREIGN KEY ("triggered_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
