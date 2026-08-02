import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { validateHealth, validateHealthURL, waitForReadiness } from "../integration/readiness.mjs";

function productionHealth(overrides = {}) {
  return {
    ok: true,
    controllerOnline: false,
    sourceOnline: false,
    mirrorCount: 0,
    activePairs: 0,
    connectedPairs: 0,
    maxPairs: 3,
    quotaProtection: true,
    extensionProtocol: "quota-v1",
    quotaChecks: 0,
    sourceAssetProxy: true,
    sourceAssetRequests: 0,
    sourceAssetCacheHits: 0,
    sourceAssetCacheEntries: 0,
    sourceAssetCacheBytes: 0,
    ...overrides,
  };
}

async function withHealthServer(handler, callback) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    return await callback(`http://127.0.0.1:${address.port}/healthz`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("health URL is constrained to an exact loopback endpoint", () => {
  assert.equal(validateHealthURL("http://127.0.0.1:3210/healthz").href, "http://127.0.0.1:3210/healthz");
  for (const unsafe of [
    "http://localhost:3210/healthz",
    "http://127.0.0.1:3210/healthz?full=true",
    "http://user@127.0.0.1:3210/healthz",
    "https://127.0.0.1:3210/healthz",
    "http://127.0.0.1:3210/",
  ]) {
    assert.throws(() => validateHealthURL(unsafe), /exact 127\.0\.0\.1/);
  }
});

test("health validation requires the complete production contract", () => {
  assert.deepEqual(validateHealth(productionHealth()), productionHealth());
  assert.throws(() => validateHealth(productionHealth({ maxPairs: 4 })), /capability contract/);
  assert.throws(() => validateHealth(productionHealth({ quotaProtection: false })), /capability contract/);
  assert.throws(() => validateHealth(productionHealth({ extensionProtocol: "legacy" })), /capability contract/);
  assert.throws(() => validateHealth(productionHealth({ activePairs: 1 })), /inconsistent connection counters/);
  assert.throws(() => validateHealth(productionHealth(), { requireController: true }), /controller is offline/);
  assert.doesNotThrow(() => validateHealth(productionHealth({ controllerOnline: true }), { requireController: true }));
});

test("readiness retries bounded failures and accepts a current controller", async () => {
  let requests = 0;
  await withHealthServer((request, response) => {
    requests += 1;
    assert.equal(request.url, "/healthz");
    assert.equal(request.headers.accept, "application/json");
    response.setHeader("content-type", "application/json; charset=utf-8");
    response.end(JSON.stringify(requests < 2 ? productionHealth() : productionHealth({ controllerOnline: true })));
  }, async (healthURL) => {
    const health = await waitForReadiness({ healthURL, timeoutMilliseconds: 2_000, requireController: true });
    assert.equal(health.controllerOnline, true);
  });
  assert.ok(requests >= 2);
});

test("readiness rejects oversized and non-JSON responses", async () => {
  await withHealthServer((_request, response) => {
    response.setHeader("content-type", "text/html");
    response.end("not JSON");
  }, async (healthURL) => {
    await assert.rejects(
      waitForReadiness({ healthURL, timeoutMilliseconds: 500 }),
      /response metadata is invalid/,
    );
  });
  await withHealthServer((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.write("{");
    response.end("x".repeat(70 * 1024));
  }, async (healthURL) => {
    await assert.rejects(
      waitForReadiness({ healthURL, timeoutMilliseconds: 500 }),
      /response (metadata|size) is invalid/,
    );
  });
});
