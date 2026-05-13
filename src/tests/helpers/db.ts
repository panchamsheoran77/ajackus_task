// Re-export the prisma client for convenience. Tests should mock this module
// via `vi.mock("@/lib/prisma", ...)` rather than touching a real database.
export { prisma } from "@/lib/prisma";
