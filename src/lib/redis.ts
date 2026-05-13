import Redis from "ioredis";

declare global {
  // eslint-disable-next-line no-var
  var __redis: Redis | undefined;
  // eslint-disable-next-line no-var
  var __redisBull: Redis | undefined;
}

const url = process.env.REDIS_URL ?? "redis://localhost:6379";

/**
 * General-purpose Redis client for cache reads/writes from API routes and
 * the worker. Reused across hot-reloads in dev via globalThis.
 */
export const redis: Redis =
  globalThis.__redis ??
  new Redis(url, {
    lazyConnect: false,
  });

if (process.env.NODE_ENV !== "production") globalThis.__redis = redis;

/**
 * Separate connection for BullMQ. BullMQ requires `maxRetriesPerRequest: null`
 * so blocking commands (BRPOPLPUSH etc.) never give up. Don't reuse this
 * client for normal SET/GET — its retry semantics differ.
 */
export const redisForBull: Redis =
  globalThis.__redisBull ??
  new Redis(url, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  });

if (process.env.NODE_ENV !== "production") globalThis.__redisBull = redisForBull;
