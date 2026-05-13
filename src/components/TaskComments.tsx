"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getStoredUser } from "@/lib/api-client";
import type { ApiComment, ApiProjectMember, Role } from "@/types";

type Props = {
  taskId: string;
  members: ApiProjectMember[];
};

function formatWhen(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function currentUserRole(members: ApiProjectMember[]): Role | null {
  const me = getStoredUser();
  if (!me) return null;
  return members.find((m) => m.user.id === me.id)?.role ?? null;
}

export function TaskComments({ taskId, members }: Props) {
  const queryClient = useQueryClient();
  const [body, setBody] = useState("");
  const [error, setError] = useState<string | null>(null);

  const role = currentUserRole(members);
  const canPost = role === "admin" || role === "member";

  const { data, isLoading } = useQuery({
    queryKey: ["task-comments", taskId],
    queryFn: () =>
      apiFetch<{ comments: ApiComment[] }>(`/api/tasks/${taskId}/comments`),
  });

  const post = useMutation({
    mutationFn: (input: { body: string }) =>
      apiFetch<{ comment: ApiComment }>(`/api/tasks/${taskId}/comments`, {
        method: "POST",
        body: JSON.stringify(input),
      }),
    onSuccess: () => {
      setBody("");
      queryClient.invalidateQueries({ queryKey: ["task-comments", taskId] });
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "post failed"),
  });

  const comments = data?.comments ?? [];

  return (
    <section className="mt-6 border-t border-border pt-4">
      <h3 className="text-sm font-medium mb-3">
        comments {comments.length > 0 && (
          <span className="text-muted">({comments.length})</span>
        )}
      </h3>

      {isLoading ? (
        <p className="text-xs text-muted">loading…</p>
      ) : comments.length === 0 ? (
        <p className="text-xs text-muted">no comments yet</p>
      ) : (
        <ul className="space-y-3 max-h-64 overflow-y-auto pr-1">
          {comments.map((c) => (
            <li
              key={c.id}
              className="rounded-md bg-bg border border-border px-3 py-2"
            >
              <div className="flex items-center justify-between text-xs text-muted mb-1">
                <span className="font-medium text-white">{c.author.name}</span>
                <time dateTime={c.createdAt}>{formatWhen(c.createdAt)}</time>
              </div>
              <p className="text-sm whitespace-pre-wrap break-words">
                {c.body}
              </p>
            </li>
          ))}
        </ul>
      )}

      {canPost ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const trimmed = body.trim();
            if (!trimmed) return;
            setError(null);
            post.mutate({ body: trimmed });
          }}
          className="mt-3"
        >
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="add a comment…"
            rows={2}
            maxLength={5000}
            className="block w-full rounded-md bg-bg border border-border px-3 py-2 text-sm focus:border-accent focus:outline-none"
          />
          {error && (
            <p className="text-xs text-red-400 mt-1" role="alert">
              {error}
            </p>
          )}
          <div className="mt-2 flex justify-end">
            <button
              type="submit"
              disabled={post.isPending || !body.trim()}
              className="text-sm px-3 py-1.5 rounded-md bg-accent text-white hover:bg-indigo-500 disabled:opacity-50"
            >
              {post.isPending ? "posting…" : "post"}
            </button>
          </div>
        </form>
      ) : (
        <p className="mt-3 text-xs text-muted">
          you have read-only access to this project
        </p>
      )}
    </section>
  );
}
