import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  getCurrentUser,
  unauthorized,
  forbidden,
  getProjectMembership,
  canEditTasks,
} from "@/lib/auth";
import { enqueueExport } from "@/lib/export-queue";
import {
  buildSnapshot,
  clearActive,
  setStatus,
  tryClaimActive,
} from "@/lib/export-status-cache";

type Params = { params: Promise<{ id: string }> };

export async function POST(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");
  if (!canEditTasks(membership.role)) {
    return forbidden("viewers cannot trigger exports");
  }

  // Create the ExportJob row first so we have a stable id for the claim.
  const job = await prisma.exportJob.create({
    data: { projectId, triggeredById: user.id, status: "queued" },
  });

  const { claimed, activeExportId } = await tryClaimActive(projectId, job.id);

  if (!claimed) {
    // Another export is already in flight. Drop the row we just created
    // (it never got enqueued) and return the active one.
    await prisma.exportJob.delete({ where: { id: job.id } }).catch(() => {});
    const existing = await prisma.exportJob.findUnique({
      where: { id: activeExportId },
    });
    if (!existing) {
      // Stale active key — clean it up and let the caller retry.
      await clearActive(projectId);
      return NextResponse.json(
        { error: "another export was just enqueued, please retry" },
        { status: 409 },
      );
    }
    return NextResponse.json(
      { snapshot: buildSnapshot(existing), alreadyRunning: true },
      { status: 200 },
    );
  }

  try {
    await enqueueExport(job.id);
  } catch (err) {
    // Failed to enqueue — release the claim and the row.
    await clearActive(projectId);
    await prisma.exportJob.delete({ where: { id: job.id } }).catch(() => {});
    return NextResponse.json(
      { error: "failed to enqueue export", details: (err as Error).message },
      { status: 503 },
    );
  }

  const snapshot = buildSnapshot(job);
  await setStatus(snapshot);

  return NextResponse.json({ snapshot }, { status: 202 });
}

export async function GET(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");

  const jobs = await prisma.exportJob.findMany({
    where: { projectId },
    orderBy: { createdAt: "desc" },
    take: 20,
  });

  return NextResponse.json({ exports: jobs.map(buildSnapshot) });
}
