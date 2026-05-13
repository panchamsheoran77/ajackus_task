"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-client";
import type { Role } from "@/types";

type ExportSnapshot = {
  exportId: string;
  projectId: string;
  status: "queued" | "running" | "succeeded" | "failed" | "stalled";
  totalTasks: number;
  successCount: number;
  failureCount: number;
  attempts: number;
  startedAt: string | null;
  finishedAt: string | null;
  heartbeatAt: string | null;
  updatedAt: string;
  errorsTruncated: boolean;
  errorsSample: { taskBoardId: string; message: string; statusCode: number | null }[];
};

type StartResponse = { snapshot: ExportSnapshot; alreadyRunning?: boolean };
type StatusResponse = { snapshot: ExportSnapshot; cached: boolean };
type ErrorsResponse = {
  exportId: string;
  failureCount: number;
  errors: { taskBoardId: string; message: string; statusCode: number | null }[];
};

const TERMINAL = new Set(["succeeded", "failed"]);

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

export function ExportToAirtableButton({
  projectId,
  currentUserRole,
}: {
  projectId: string;
  currentUserRole: Role | null;
}) {
  const canTrigger = currentUserRole === "admin" || currentUserRole === "member";
  const [exportId, setExportId] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<ExportSnapshot | null>(null);
  const [showErrors, setShowErrors] = useState(false);
  const [bannerError, setBannerError] = useState<string | null>(null);

  const start = useMutation({
    mutationFn: () =>
      apiFetch<StartResponse>(`/api/projects/${projectId}/exports`, {
        method: "POST",
      }),
    onSuccess: (data) => {
      setExportId(data.snapshot.exportId);
      setSnapshot(data.snapshot);
      setBannerError(null);
    },
    onError: (err) =>
      setBannerError(err instanceof Error ? err.message : "failed to start export"),
  });

  const status = useQuery({
    queryKey: ["export-status", projectId, exportId],
    queryFn: () =>
      apiFetch<StatusResponse>(
        `/api/projects/${projectId}/exports/${exportId}`,
      ),
    enabled: false, // user-initiated only
  });

  const errors = useQuery({
    queryKey: ["export-errors", projectId, exportId],
    queryFn: () =>
      apiFetch<ErrorsResponse>(
        `/api/projects/${projectId}/exports/${exportId}/errors`,
      ),
    enabled: false,
  });

  async function onRefresh() {
    if (!exportId) return;
    const { data } = await status.refetch();
    if (data) setSnapshot(data.snapshot);
  }

  async function onToggleErrors() {
    setShowErrors((v) => !v);
    if (!showErrors && exportId && !errors.data) {
      await errors.refetch();
    }
  }

  if (!canTrigger) return null;

  if (!snapshot) {
    return (
      <div>
        <button
          onClick={() => start.mutate()}
          disabled={start.isPending}
          className="bg-accent hover:bg-indigo-500 text-white text-sm font-medium rounded-md px-4 py-2 disabled:opacity-50"
        >
          {start.isPending ? "starting…" : "export to airtable"}
        </button>
        {bannerError && (
          <p className="text-sm text-red-400 mt-2" role="alert">
            {bannerError}
          </p>
        )}
      </div>
    );
  }

  const isTerminal = TERMINAL.has(snapshot.status);
  const isStalled = snapshot.status === "stalled";

  return (
    <div className="bg-surface border border-border rounded-lg p-4 max-w-md">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium">export to airtable</h3>
        <span
          className={
            "text-xs px-2 py-0.5 rounded-full " +
            (snapshot.status === "succeeded"
              ? "bg-green-900 text-green-200"
              : snapshot.status === "failed"
                ? "bg-red-900 text-red-200"
                : isStalled
                  ? "bg-yellow-900 text-yellow-200"
                  : "bg-indigo-900 text-indigo-200")
          }
        >
          {snapshot.status}
        </span>
      </div>

      <p className="text-sm">
        {snapshot.successCount.toLocaleString()} /{" "}
        {snapshot.totalTasks.toLocaleString()} tasks
        {snapshot.failureCount > 0 && (
          <span className="text-red-300">
            {" "}
            · {snapshot.failureCount} failure
            {snapshot.failureCount === 1 ? "" : "s"}
          </span>
        )}
      </p>

      <p className="text-xs text-muted mt-1">
        started {relativeTime(snapshot.startedAt)}
        {isTerminal && snapshot.finishedAt
          ? ` · finished ${relativeTime(snapshot.finishedAt)}`
          : ` · refreshed ${relativeTime(snapshot.updatedAt)}`}
      </p>

      {!isTerminal && (
        <div className="flex items-center gap-2 mt-3">
          <button
            onClick={onRefresh}
            disabled={status.isFetching}
            className="text-sm border border-border rounded-md px-3 py-1 hover:border-accent disabled:opacity-50"
          >
            {status.isFetching ? "refreshing…" : "⟲ refresh"}
          </button>
        </div>
      )}

      {isTerminal && (
        <div className="mt-3">
          <button
            onClick={() => {
              setSnapshot(null);
              setExportId(null);
              setShowErrors(false);
            }}
            className="text-sm border border-border rounded-md px-3 py-1 hover:border-accent"
          >
            done · run again
          </button>
        </div>
      )}

      {snapshot.failureCount > 0 && (
        <div className="mt-3">
          <button
            onClick={onToggleErrors}
            className="text-xs text-muted hover:text-white"
          >
            {showErrors ? "▾" : "▸"} view {snapshot.failureCount} error
            {snapshot.failureCount === 1 ? "" : "s"}
          </button>
          {showErrors && (
            <ul className="mt-2 text-xs space-y-1 max-h-40 overflow-auto">
              {errors.isFetching && <li className="text-muted">loading…</li>}
              {(errors.data?.errors ?? snapshot.errorsSample).map((e, i) => (
                <li key={i} className="text-red-300">
                  <span className="text-muted">{e.taskBoardId}:</span>{" "}
                  {e.message}
                  {e.statusCode != null && (
                    <span className="text-muted"> [{e.statusCode}]</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
