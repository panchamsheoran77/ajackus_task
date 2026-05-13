import { NextRequest } from "next/server";
import { signToken } from "@/lib/jwt";

export function mintToken(userId: string, email: string): string {
  return signToken({ userId, email });
}

export function newGetRequest(url: string, bearer?: string): NextRequest {
  const headers = new Headers();
  if (bearer) headers.set("Authorization", `Bearer ${bearer}`);
  return new NextRequest(new URL(url), { method: "GET", headers });
}

export function newPostRequest(
  url: string,
  body: unknown,
  bearer?: string,
): NextRequest {
  const headers = new Headers();
  headers.set("Content-Type", "application/json");
  if (bearer) headers.set("Authorization", `Bearer ${bearer}`);
  return new NextRequest(new URL(url), {
    method: "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export type RouteParams = { params: Promise<{ id: string }> };

export function paramsFor(id: string): RouteParams {
  return { params: Promise.resolve({ id }) };
}
