// @vitest-environment node
import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";

vi.mock("@/lib/prisma", () => ({
  prisma: {
    user: { findUnique: vi.fn() },
    membership: { findUnique: vi.fn() },
    task: { findUnique: vi.fn() },
    comment: {
      findMany: vi.fn(),
      create: vi.fn(),
    },
  },
}));

import * as route from "@/app/api/tasks/[id]/comments/route";
import { GET, POST } from "@/app/api/tasks/[id]/comments/route";
import { prisma } from "@/lib/prisma";
import {
  mintToken,
  newGetRequest,
  newPostRequest,
  paramsFor,
} from "@/tests/helpers/http";

const MEERA = { id: "u_meera", email: "meera@taskboard.dev", name: "Meera" };
const KAVYA = { id: "u_kavya", email: "kavya@example.com", name: "Kavya" };
const DEV = { id: "u_dev", email: "dev@example.com", name: "Dev" };
const TASK_ID = "t_1";
const PROJECT_ID = "p_q3";

function asMock<T extends (...args: never[]) => unknown>(fn: T): Mock {
  return fn as unknown as Mock;
}

beforeEach(() => {
  vi.clearAllMocks();
  asMock(prisma.user.findUnique).mockResolvedValue(MEERA);
  asMock(prisma.membership.findUnique).mockResolvedValue({ role: "member" });
  asMock(prisma.task.findUnique).mockResolvedValue({ projectId: PROJECT_ID });
  asMock(prisma.comment.findMany).mockResolvedValue([]);
  asMock(prisma.comment.create).mockImplementation(async (args) => ({
    id: "c_new",
    taskId: TASK_ID,
    authorId: MEERA.id,
    body: args.data.body,
    createdAt: new Date(),
    author: { id: MEERA.id, name: MEERA.name, email: MEERA.email },
  }));
});

async function callGet(opts: {
  user?: { id: string; email: string };
  taskId?: string;
  bearer?: string | null;
}) {
  const taskId = opts.taskId ?? TASK_ID;
  const user = opts.user ?? MEERA;
  const bearer =
    opts.bearer === null
      ? undefined
      : (opts.bearer ?? mintToken(user.id, user.email));
  const req = newGetRequest(
    `http://localhost/api/tasks/${taskId}/comments`,
    bearer,
  );
  return await GET(req, paramsFor(taskId));
}

async function callPost(opts: {
  user?: { id: string; email: string };
  taskId?: string;
  body?: unknown;
  bearer?: string | null;
}) {
  const taskId = opts.taskId ?? TASK_ID;
  const user = opts.user ?? MEERA;
  const bearer =
    opts.bearer === null
      ? undefined
      : (opts.bearer ?? mintToken(user.id, user.email));
  const payload = "body" in opts ? opts.body : { body: "looks good" };
  const req = newPostRequest(
    `http://localhost/api/tasks/${taskId}/comments`,
    payload,
    bearer,
  );
  return await POST(req, paramsFor(taskId));
}

// =====================================================================
// Append-only contract — the route must NEVER expose edit/delete
// =====================================================================
describe("comments route — append-only contract", () => {
  it("does not export PATCH / PUT / DELETE handlers", () => {
    const r = route as Record<string, unknown>;
    expect(r.PATCH).toBeUndefined();
    expect(r.PUT).toBeUndefined();
    expect(r.DELETE).toBeUndefined();
  });
});

// =====================================================================
// Authentication
// =====================================================================
describe("GET /api/tasks/:id/comments — auth", () => {
  it("401 without bearer token", async () => {
    const res = await callGet({ bearer: null });
    expect(res.status).toBe(401);
    expect(prisma.comment.findMany).not.toHaveBeenCalled();
  });

  it("401 with malformed bearer", async () => {
    const res = await callGet({ bearer: "not.a.real.token" });
    expect(res.status).toBe(401);
    expect(prisma.comment.findMany).not.toHaveBeenCalled();
  });

  it("401 if JWT references a user that no longer exists", async () => {
    asMock(prisma.user.findUnique).mockResolvedValue(null);
    const res = await callGet({});
    expect(res.status).toBe(401);
    expect(prisma.comment.findMany).not.toHaveBeenCalled();
  });
});

describe("POST /api/tasks/:id/comments — auth", () => {
  it("401 without bearer token", async () => {
    const res = await callPost({ bearer: null });
    expect(res.status).toBe(401);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("401 with malformed bearer", async () => {
    const res = await callPost({ bearer: "not.a.real.token" });
    expect(res.status).toBe(401);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("401 if JWT references a user that no longer exists", async () => {
    asMock(prisma.user.findUnique).mockResolvedValue(null);
    const res = await callPost({});
    expect(res.status).toBe(401);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });
});

// =====================================================================
// Task existence
// =====================================================================
describe("comments route — task existence", () => {
  it("GET returns 404 if task does not exist", async () => {
    asMock(prisma.task.findUnique).mockResolvedValue(null);
    const res = await callGet({});
    expect(res.status).toBe(404);
    expect(prisma.comment.findMany).not.toHaveBeenCalled();
  });

  it("POST returns 404 if task does not exist", async () => {
    asMock(prisma.task.findUnique).mockResolvedValue(null);
    const res = await callPost({});
    expect(res.status).toBe(404);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });
});

// =====================================================================
// Membership / role
// =====================================================================
describe("GET /api/tasks/:id/comments — read access", () => {
  it("403 when caller is not a member of the parent project", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue(null);
    const res = await callGet({});
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("you are not a member of this project");
    expect(prisma.comment.findMany).not.toHaveBeenCalled();
  });

  it.each(["viewer", "member", "admin"] as const)(
    "allows role=%s to read",
    async (role) => {
      asMock(prisma.membership.findUnique).mockResolvedValue({ role });
      const res = await callGet({ user: KAVYA });
      expect(res.status).toBe(200);
    },
  );
});

describe("POST /api/tasks/:id/comments — write access", () => {
  it("403 when caller is not a member of the parent project", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue(null);
    const res = await callPost({});
    expect(res.status).toBe(403);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("403 when caller is a viewer (read-only role cannot post)", async () => {
    asMock(prisma.membership.findUnique).mockResolvedValue({ role: "viewer" });
    const res = await callPost({ user: DEV });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("viewers cannot post comments");
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it.each(["member", "admin"] as const)(
    "allows role=%s to post",
    async (role) => {
      asMock(prisma.membership.findUnique).mockResolvedValue({ role });
      const res = await callPost({});
      expect(res.status).toBe(201);
      expect(prisma.comment.create).toHaveBeenCalledTimes(1);
    },
  );
});

// =====================================================================
// Validation
// =====================================================================
describe("POST /api/tasks/:id/comments — validation", () => {
  it("400 on empty body", async () => {
    const res = await callPost({ body: { body: "" } });
    expect(res.status).toBe(400);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("400 on whitespace-only body", async () => {
    const res = await callPost({ body: { body: "   \n\t  " } });
    expect(res.status).toBe(400);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("400 when body exceeds 5000 chars", async () => {
    const res = await callPost({ body: { body: "x".repeat(5001) } });
    expect(res.status).toBe(400);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("400 on completely missing JSON", async () => {
    const res = await callPost({ body: null });
    expect(res.status).toBe(400);
    expect(prisma.comment.create).not.toHaveBeenCalled();
  });

  it("trims surrounding whitespace before persisting", async () => {
    await callPost({ body: { body: "  hello world  " } });
    const arg = asMock(prisma.comment.create).mock.calls[0][0];
    expect(arg.data.body).toBe("hello world");
  });
});

// =====================================================================
// Behaviour: chronology, isolation, payload shape
// =====================================================================
describe("GET /api/tasks/:id/comments — behaviour", () => {
  it("orders comments chronologically (createdAt asc)", async () => {
    await callGet({});
    const arg = asMock(prisma.comment.findMany).mock.calls[0][0];
    expect(arg.orderBy).toEqual({ createdAt: "asc" });
  });

  it("scopes findMany WHERE to the URL's :id (cross-task isolation)", async () => {
    await callGet({ taskId: TASK_ID });
    const arg = asMock(prisma.comment.findMany).mock.calls[0][0];
    expect(arg.where.taskId).toBe(TASK_ID);
  });

  it("includes the author with a safe field projection (no passwordHash)", async () => {
    await callGet({});
    const arg = asMock(prisma.comment.findMany).mock.calls[0][0];
    expect(arg.include.author.select).toEqual({
      id: true,
      name: true,
      email: true,
    });
  });

  it("returns whatever the data layer returns under `comments`", async () => {
    const rows = [
      {
        id: "c1",
        taskId: TASK_ID,
        authorId: MEERA.id,
        body: "first",
        createdAt: new Date("2026-01-01T00:00:00Z"),
        author: { id: MEERA.id, name: MEERA.name, email: MEERA.email },
      },
    ];
    asMock(prisma.comment.findMany).mockResolvedValue(rows);
    const res = await callGet({});
    const body = await res.json();
    expect(body.comments).toHaveLength(1);
    expect(body.comments[0].body).toBe("first");
    expect(body.comments[0].author.email).toBe(MEERA.email);
  });
});

describe("POST /api/tasks/:id/comments — behaviour", () => {
  it("persists with authorId = current user, taskId = URL param", async () => {
    await callPost({ user: MEERA, body: { body: "ship it" } });
    const arg = asMock(prisma.comment.create).mock.calls[0][0];
    expect(arg.data.authorId).toBe(MEERA.id);
    expect(arg.data.taskId).toBe(TASK_ID);
    expect(arg.data.body).toBe("ship it");
  });

  it("returns the created comment under `comment`, status 201", async () => {
    const res = await callPost({});
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.comment.author.email).toBe(MEERA.email);
  });

  it("includes the author projection on create (no passwordHash leak)", async () => {
    await callPost({});
    const arg = asMock(prisma.comment.create).mock.calls[0][0];
    expect(arg.include.author.select).toEqual({
      id: true,
      name: true,
      email: true,
    });
  });

  it("never accepts a client-supplied authorId (cannot impersonate)", async () => {
    await callPost({
      user: MEERA,
      body: { body: "spoof", authorId: "u_someone_else" },
    });
    const arg = asMock(prisma.comment.create).mock.calls[0][0];
    expect(arg.data.authorId).toBe(MEERA.id);
  });
});
