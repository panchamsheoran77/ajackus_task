import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  getCurrentUser,
  unauthorized,
  forbidden,
  notFound,
  getProjectMembership,
} from "@/lib/auth";

type Params = { params: Promise<{ id: string; exportId: string }> };

export async function GET(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId, exportId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");

  const job = await prisma.exportJob.findUnique({
    where: { id: exportId },
    select: { id: true, projectId: true, errors: true, failureCount: true },
  });
  if (!job || job.projectId !== projectId) return notFound("export not found");

  return NextResponse.json({
    exportId: job.id,
    failureCount: job.failureCount,
    errors: Array.isArray(job.errors) ? job.errors : [],
  });
}
