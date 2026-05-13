/**
 * Real Airtable client wrapper.
 *
 * Exposes `upsertBatch` which calls the Airtable `update` endpoint with the
 * `performUpsert` option keyed on `TaskBoardId`. Wraps every call in a retry
 * loop that classifies errors as transient / permanent / per-record.
 *
 * Idempotency lives in Airtable: re-running the export is a no-op for any
 * record whose `TaskBoardId` already exists.
 */

import Airtable, { type FieldSet, type Table } from "airtable";

export type TaskFields = {
  TaskBoardId: string;
  Title: string;
  Description: string | null;
  Status: "todo" | "in_progress" | "review" | "done";
  Assignee: string | null;
  CreatedAt: string;
  UpdatedAt: string;
};

export type RecordError = {
  taskBoardId: string;
  message: string;
  statusCode: number | null;
};

export type UpsertBatchResult = {
  successCount: number;
  failures: RecordError[];
};

export class UnrecoverableExportError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
  ) {
    super(message);
    this.name = "UnrecoverableExportError";
  }
}

const MAX_ATTEMPTS = 5;
const BASE_DELAY_MS = 250;
const MAX_DELAY_MS = 8000;

function isPermanent(statusCode: number): boolean {
  // 401/403 = auth, 404 = base/table missing.
  // 422 is partial — handled separately at the batch level (see below).
  return statusCode === 401 || statusCode === 403 || statusCode === 404;
}

function isTransient(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500 || statusCode === 0;
}

function backoffMs(attempt: number, retryAfter: number | null): number {
  if (retryAfter != null && retryAfter > 0) return retryAfter * 1000;
  const cap = Math.min(BASE_DELAY_MS * Math.pow(2, attempt - 1), MAX_DELAY_MS);
  return Math.floor(Math.random() * cap);
}

function getStatusCode(err: unknown): number {
  if (err && typeof err === "object" && "statusCode" in err) {
    const sc = (err as { statusCode: unknown }).statusCode;
    if (typeof sc === "number") return sc;
  }
  // Airtable's SDK sometimes uses `error` field for the code in older shapes.
  if (err && typeof err === "object" && "error" in err) {
    const code = (err as { error: unknown }).error;
    if (typeof code === "number") return code;
  }
  return 0;
}

function getRetryAfter(err: unknown): number | null {
  if (err && typeof err === "object" && "retryAfter" in err) {
    const ra = (err as { retryAfter: unknown }).retryAfter;
    if (typeof ra === "number") return ra;
  }
  return null;
}

function getMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return String(err);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Run an Airtable call with retry on transient failures.
 * Throws `UnrecoverableExportError` on permanent failures (caller should
 * abort the whole job).
 */
async function withRetry<T>(call: () => Promise<T>, label: string): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      return await call();
    } catch (err) {
      lastErr = err;
      const status = getStatusCode(err);
      if (isPermanent(status)) {
        throw new UnrecoverableExportError(
          `${label}: ${getMessage(err)} (status ${status})`,
          status,
        );
      }
      if (!isTransient(status)) {
        // 422 / 400 etc. — surface to caller so it can do per-record fallback.
        throw err;
      }
      if (attempt === MAX_ATTEMPTS) break;
      await sleep(backoffMs(attempt, getRetryAfter(err)));
    }
  }
  // Out of attempts on transient errors — let the caller decide what to do.
  throw lastErr;
}

type Opts = {
  typecast?: boolean;
  performUpsert?: { fieldsToMergeOn: string[] };
};

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env var: ${name}`);
  return v;
}

declare global {
  // eslint-disable-next-line no-var
  var __airtableTable: Table<FieldSet> | undefined;
}

export function getAirtableTable(): Table<FieldSet> {
  if (globalThis.__airtableTable) return globalThis.__airtableTable;
  const apiKey = requireEnv("AIRTABLE_API_KEY");
  const baseId = requireEnv("AIRTABLE_BASE_ID");
  const tableName = process.env.AIRTABLE_TABLE_NAME ?? "Tasks";
  const table = new Airtable({ apiKey }).base(baseId).table<FieldSet>(tableName);
  if (process.env.NODE_ENV !== "production") globalThis.__airtableTable = table;
  return table;
}

type UpsertCaller = (
  records: { fields: TaskFields }[],
  opts: Opts,
) => Promise<unknown>;

function defaultUpsertCaller(): UpsertCaller {
  const table = getAirtableTable();
  return (records, opts) =>
    // The public type doesn't expose `performUpsert`, but the SDK forwards
    // unknown opts straight to the API body (see node_modules/airtable/lib/table.js).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (table.update as any)(records as unknown as never, opts);
}

/**
 * Upsert a batch of up to 10 records using `performUpsert` keyed on TaskBoardId.
 * Returns a per-batch result. Per-record permanent errors (422/400) are
 * recorded as failures so the export keeps going.
 */
export async function upsertBatch(
  records: { fields: TaskFields }[],
  caller: UpsertCaller = defaultUpsertCaller(),
): Promise<UpsertBatchResult> {
  if (records.length === 0) return { successCount: 0, failures: [] };

  const opts: Opts = {
    typecast: true,
    performUpsert: { fieldsToMergeOn: ["TaskBoardId"] },
  };

  try {
    await withRetry(() => caller(records, opts), "upsertBatch");
    return { successCount: records.length, failures: [] };
  } catch (err) {
    if (err instanceof UnrecoverableExportError) throw err;

    const status = getStatusCode(err);
    // 422 or 400 on a whole batch usually means at least one record is bad.
    // Fall back to per-record upserts so the rest still land.
    if (status === 422 || status === 400) {
      return await perRecordFallback(records, caller);
    }
    // Transient ran out of retries — surface to caller (worker will retry the job).
    throw err;
  }
}

async function perRecordFallback(
  records: { fields: TaskFields }[],
  caller: UpsertCaller,
): Promise<UpsertBatchResult> {
  const opts: Opts = {
    typecast: true,
    performUpsert: { fieldsToMergeOn: ["TaskBoardId"] },
  };

  let successCount = 0;
  const failures: RecordError[] = [];

  for (const rec of records) {
    try {
      await withRetry(() => caller([rec], opts), "upsertBatch (single)");
      successCount++;
    } catch (err) {
      if (err instanceof UnrecoverableExportError) throw err;
      const status = getStatusCode(err);
      // Transient still couldn't go through — record as a failure but don't
      // abort the job; on the next attempt the cursor brings us back here
      // and the upsert is idempotent.
      failures.push({
        taskBoardId: rec.fields.TaskBoardId,
        message: getMessage(err),
        statusCode: status || null,
      });
    }
  }

  return { successCount, failures };
}

// Test seam: allow tests to inject a fake caller without setting env vars.
export const __internals = {
  withRetry,
  isPermanent,
  isTransient,
};
