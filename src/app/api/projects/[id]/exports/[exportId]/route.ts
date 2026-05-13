import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  getCurrentUser,
  unauthorized,
  forbidden,
  notFound,
  getProjectMembership,
} from "@/lib/auth";
import {
  buildSnapshot,
  getStatus,
  setStatus,
} from "@/lib/export-status-cache";

type Params = { params: Promise<{ id: string; exportId: string }> };

export async function GET(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId, exportId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");

  // Redis-first.
  const cached = await getStatus(exportId);
  if (cached && cached.projectId === projectId) {
    return NextResponse.json({ snapshot: cached, cached: true });
  }

  // Cache miss — fall through to DB and backfill.
  const job = await prisma.exportJob.findUnique({ where: { id: exportId } });
  if (!job || job.projectId !== projectId) return notFound("export not found");

  const snapshot = buildSnapshot(job);
  await setStatus(snapshot);
  return NextResponse.json({ snapshot, cached: false });
}
