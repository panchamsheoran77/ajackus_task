import "@testing-library/jest-dom/vitest";

process.env.JWT_SECRET = process.env.JWT_SECRET || "test-secret";
// Tests mock @/lib/prisma; DATABASE_URL only needs to satisfy Prisma's
// generator-time parse — any well-formed URL works.
process.env.DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://test:test@127.0.0.1:5432/test?schema=public";
