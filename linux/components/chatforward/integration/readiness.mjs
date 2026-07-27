#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const maximumHealthBytes = 64 * 1024;
const defaultHealthURL = "http://127.0.0.1:3210/healthz";

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

async function readBoundedBody(response) {
  if (!response.body) throw new Error("health response body is missing");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumHealthBytes) {
        await reader.cancel();
        throw new Error("health response size is invalid");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  if (size === 0) throw new Error("health response size is invalid");
  return Buffer.concat(chunks, size).toString("utf8");
}

export function validateHealthURL(rawURL) {
  const target = new URL(rawURL);
  if (
    target.protocol !== "http:" ||
    target.hostname !== "127.0.0.1" ||
    !target.port ||
    target.pathname !== "/healthz" ||
    target.username ||
    target.password ||
    target.search ||
    target.hash
  ) {
    throw new Error("health URL must be an exact 127.0.0.1 HTTP /healthz URL");
  }
  return target;
}

export function validateHealth(payload, { requireController = false } = {}) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("health response is not an object");
  }
  if (
    payload.ok !== true ||
    payload.quotaProtection !== true ||
    payload.extensionProtocol !== "quota-v1" ||
    payload.sourceAssetProxy !== true ||
    payload.maxPairs !== 3
  ) {
    throw new Error("health response does not advertise the production capability contract");
  }
  for (const name of [
    "mirrorCount",
    "activePairs",
    "connectedPairs",
    "quotaChecks",
    "sourceAssetRequests",
    "sourceAssetCacheHits",
    "sourceAssetCacheEntries",
    "sourceAssetCacheBytes",
  ]) {
    if (!nonNegativeInteger(payload[name])) {
      throw new Error(`health response contains invalid ${name}`);
    }
  }
  if (
    payload.mirrorCount !== payload.activePairs ||
    payload.activePairs > payload.maxPairs ||
    payload.connectedPairs > payload.activePairs ||
    typeof payload.controllerOnline !== "boolean" ||
    typeof payload.sourceOnline !== "boolean" ||
    payload.sourceOnline !== (payload.connectedPairs > 0)
  ) {
    throw new Error("health response contains inconsistent connection counters");
  }
  if (requireController && payload.controllerOnline !== true) {
    throw new Error("ChatForward Chromium controller is offline");
  }
  return payload;
}

export async function waitForReadiness({
  healthURL = defaultHealthURL,
  timeoutMilliseconds = 15_000,
  requireController = false,
  fetchImplementation = fetch,
} = {}) {
  const target = validateHealthURL(healthURL);
  if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds < 100 || timeoutMilliseconds > 120_000) {
    throw new Error("readiness timeout must be between 100 and 120000 milliseconds");
  }
  const deadline = Date.now() + timeoutMilliseconds;
  let lastError = null;
  do {
    const controller = new AbortController();
    const remaining = Math.max(1, deadline - Date.now());
    const timer = setTimeout(() => controller.abort(), Math.min(2_000, remaining));
    try {
      const response = await fetchImplementation(target, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        cache: "no-store",
        signal: controller.signal,
      });
      if (!response.ok || response.status !== 200) throw new Error(`health returned HTTP ${response.status}`);
      const contentType = response.headers.get("content-type") || "";
      const contentLength = response.headers.get("content-length");
      if (
        !contentType.toLowerCase().startsWith("application/json") ||
        (contentLength !== null && (!/^[0-9]+$/.test(contentLength) || Number(contentLength) > maximumHealthBytes))
      ) {
        throw new Error("health response metadata is invalid");
      }
      const body = await readBoundedBody(response);
      return validateHealth(JSON.parse(body), { requireController });
    } catch (error) {
      const candidate = error instanceof Error ? error : new Error(String(error));
      if (!lastError || candidate.name !== "AbortError") lastError = candidate;
    } finally {
      clearTimeout(timer);
    }
    if (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(200, deadline - Date.now())));
    }
  } while (Date.now() < deadline);
  throw new Error(`ChatForward readiness failed: ${lastError?.message || "endpoint did not respond"}`);
}

function parseArguments(argv) {
  let healthURL = defaultHealthURL;
  let timeoutMilliseconds = 15_000;
  let requireController = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--health-url" && argv[index + 1]) healthURL = argv[++index];
    else if (argument === "--timeout-ms" && argv[index + 1]) timeoutMilliseconds = Number(argv[++index]);
    else if (argument === "--require-controller") requireController = true;
    else throw new Error(`unknown readiness argument: ${argument}`);
  }
  return { healthURL, timeoutMilliseconds, requireController };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const result = await waitForReadiness(parseArguments(process.argv.slice(2)));
    process.stdout.write(`ChatForward ready: active=${result.activePairs}/${result.maxPairs} controller=${result.controllerOnline}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
