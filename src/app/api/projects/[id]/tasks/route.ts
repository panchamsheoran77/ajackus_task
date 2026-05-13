import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  getCurrentUser,
  unauthorized,
  forbidden,
  badRequest,
  getProjectMembership,
  canEditTasks,
} from "@/lib/auth";
import { createTaskSchema } from "@/schemas/task";

type Params = { params: Promise<{ id: string }> };

export async function GET(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");

  const q = req.nextUrl.searchParams.get("q");

  if (q) {
    const tasks = await prisma.task.findMany({
      where: {
        projectId,
        OR: [
          { title:       { contains: q, mode: "insensitive" } },
          { description: { contains: q, mode: "insensitive" } },
        ],
      },
      include: {
        assignee: { select: { id: true, name: true, email: true } },
      },
      orderBy: { position: "asc" },
    });
    return NextResponse.json({ tasks });
  }

  const tasks = await prisma.task.findMany({
    where: { projectId },
    include: {
      assignee: { select: { id: true, name: true, email: true } },
    },
    orderBy: [{ status: "asc" }, { position: "asc" }],
  });

  return NextResponse.json({ tasks });
}

export async function POST(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");
  if (!canEditTasks(membership.role)) {
    return forbidden("viewers cannot create tasks");
  }

  const body = await req.json().catch(() => null);
  const parsed = createTaskSchema.safeParse(body);
  if (!parsed.success) return badRequest("invalid input", parsed.error.flatten());

  const status = parsed.data.status ?? "todo";

  // place new task at the end of its column
  const last = await prisma.task.findFirst({
    where: { projectId, status },
    orderBy: { position: "desc" },
    select: { position: true },
  });

  const task = await prisma.task.create({
    data: {
      projectId,
      title: parsed.data.title,
      description: parsed.data.description,
      status,
      assigneeId: parsed.data.assigneeId ?? null,
      createdById: user.id,
      position: (last?.position ?? -1) + 1,
    },
    include: {
      assignee: { select: { id: true, name: true, email: true } },
    },
  });

  return NextResponse.json({ task }, { status: 201 });
}
