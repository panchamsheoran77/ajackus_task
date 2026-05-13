// @vitest-environment node
import { describe, it, expect, vi } from "vitest";
import { upsertBatch, UnrecoverableExportError, type TaskFields } from "@/lib/airtable";

function makeRecord(id: string): { fields: TaskFields } {
  return {
    fields: {
      TaskBoardId: id,
      Title: `task ${id}`,
      Description: null,
      Status: "todo",
      Assignee: null,
      CreatedAt: "2026-05-13T00:00:00.000Z",
      UpdatedAt: "2026-05-13T00:00:00.000Z",
    },
  };
}

type AirtableErr = { statusCode: number; message: string };
function err(statusCode: number, message = "boom"): AirtableErr {
  return { statusCode, message };
}

describe("upsertBatch retry classifier", () => {
  it("succeeds on first attempt with no retries", async () => {
    const caller = vi.fn().mockResolvedValue(undefined);
    const result = await upsertBatch([makeRecord("a")], caller);
    expect(result).toEqual({ successCount: 1, failures: [] });
    expect(caller).toHaveBeenCalledTimes(1);
  });

  it("retries transient 429 and eventually succeeds", async () => {
    const caller = vi
      .fn()
      .mockRejectedValueOnce(err(429))
      .mockRejectedValueOnce(err(429))
      .mockResolvedValueOnce(undefined);
    const result = await upsertBatch([makeRecord("a")], caller);
    expect(result.successCount).toBe(1);
    expect(caller).toHaveBeenCalledTimes(3);
  });

  it("retries transient 500 and eventually succeeds", async () => {
    const caller = vi
      .fn()
      .mockRejectedValueOnce(err(500))
      .mockResolvedValueOnce(undefined);
    const result = await upsertBatch([makeRecord("a")], caller);
    expect(result.successCount).toBe(1);
    expect(caller).toHaveBeenCalledTimes(2);
  });

  it("retries network errors (statusCode 0)", async () => {
    const caller = vi
      .fn()
      .mockRejectedValueOnce(err(0))
      .mockResolvedValueOnce(undefined);
    const result = await upsertBatch([makeRecord("a")], caller);
    expect(result.successCount).toBe(1);
    expect(caller).toHaveBeenCalledTimes(2);
  });

  it("gives up after max attempts on persistent transient errors", async () => {
    const caller = vi.fn().mockRejectedValue(err(503));
    await expect(upsertBatch([makeRecord("a")], caller)).rejects.toBeDefined();
    expect(caller).toHaveBeenCalledTimes(5);
  });

  it.each([401, 403, 404])(
    "throws UnrecoverableExportError on permanent %s without retrying",
    async (status) => {
      const caller = vi.fn().mockRejectedValue(err(status));
      await expect(upsertBatch([makeRecord("a")], caller)).rejects.toBeInstanceOf(
        UnrecoverableExportError,
      );
      expect(caller).toHaveBeenCalledTimes(1);
    },
  );

  it("on 422 batch error, falls back to per-record upserts; bad row recorded, others land", async () => {
    const records = [makeRecord("a"), makeRecord("b"), makeRecord("c")];
    const caller = vi.fn((recs: { fields: TaskFields }[]) => {
      if (recs.length > 1) return Promise.reject(err(422, "invalid field"));
      // per-record retry
      if (recs[0].fields.TaskBoardId === "b") {
        return Promise.reject(err(422, "bad row"));
      }
      return Promise.resolve(undefined);
    });

    const result = await upsertBatch(records, caller);
    expect(result.successCount).toBe(2);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0].taskBoardId).toBe("b");
    expect(result.failures[0].statusCode).toBe(422);
  });

  it("on 400 batch error, falls back to per-record too", async () => {
    const records = [makeRecord("a"), makeRecord("b")];
    const caller = vi.fn((recs: { fields: TaskFields }[]) => {
      if (recs.length > 1) return Promise.reject(err(400, "bad batch"));
      return Promise.resolve(undefined);
    });
    const result = await upsertBatch(records, caller);
    expect(result.successCount).toBe(2);
    expect(result.failures).toHaveLength(0);
  });

  it("a permanent error during per-record fallback still aborts the job", async () => {
    const records = [makeRecord("a"), makeRecord("b")];
    const caller = vi.fn((recs: { fields: TaskFields }[]) => {
      if (recs.length > 1) return Promise.reject(err(422));
      if (recs[0].fields.TaskBoardId === "b") return Promise.reject(err(403));
      return Promise.resolve(undefined);
    });
    await expect(upsertBatch(records, caller)).rejects.toBeInstanceOf(
      UnrecoverableExportError,
    );
  });

  it("empty input is a no-op", async () => {
    const caller = vi.fn();
    const result = await upsertBatch([], caller);
    expect(result).toEqual({ successCount: 0, failures: [] });
    expect(caller).not.toHaveBeenCalled();
  });
});
