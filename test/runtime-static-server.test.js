import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  RuntimeStaticServerError,
  startRuntimeStaticServer,
} from "../src/runtime/static-server.js";

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-runtime-static-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "dist", "assets"), { recursive: true });
  await fs.writeFile(path.join(root, "dist", "index.html"), "<!doctype html><title>Built site</title><main>Ready</main>");
  await fs.writeFile(path.join(root, "dist", "assets", "app.css"), "body { color: #123; }");
  await fs.writeFile(path.join(root, "dist", "data.bin"), "unsupported");
  await fs.writeFile(path.join(root, "dist", ".env"), "SECRET=must-not-serve");
  await fs.writeFile(path.join(root, "outside.txt"), "outside");
  return root;
}

function request(url, { method = "GET", rawPath } = {}) {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const message = http.request({
      host: parsed.hostname,
      port: parsed.port,
      path: rawPath ?? `${parsed.pathname}${parsed.search}`,
      method,
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    message.on("error", reject);
    message.end();
  });
}

test("static runtime server requires explicit opt-in and an explicit non-root directory", async (t) => {
  const root = await fixture(t);
  await assert.rejects(
    startRuntimeStaticServer({ root, directory: "dist" }),
    (error) => error instanceof RuntimeStaticServerError && error.code === "RUNTIME_STATIC_OPT_IN_REQUIRED",
  );
  await assert.rejects(
    startRuntimeStaticServer({ enabled: true, root }),
    (error) => error?.code === "STATIC_DIRECTORY_REQUIRED",
  );
  await assert.rejects(
    startRuntimeStaticServer({ enabled: true, root, directory: "." }),
    (error) => error?.code === "UNSAFE_STATIC_DIRECTORY",
  );
  await assert.rejects(
    startRuntimeStaticServer({ enabled: true, root, directory: ".." }),
    (error) => error?.code === "UNSAFE_STATIC_DIRECTORY",
  );
});

test("static runtime server binds to loopback, serves allowlisted assets and closes idempotently", async (t) => {
  const root = await fixture(t);
  const server = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
  t.after(() => server.close());

  assert.equal(server.host, "127.0.0.1");
  assert.ok(server.port > 0);
  assert.equal(server.repositoryScriptsExecuted, false);
  const document = await request(server.url);
  assert.equal(document.status, 200);
  assert.match(document.body, /Built site/);
  assert.match(document.headers["content-type"], /^text\/html/);
  assert.equal(document.headers["x-content-type-options"], "nosniff");
  assert.equal(document.headers["cache-control"], "no-store");

  const css = await request(new URL("assets/app.css", server.url));
  assert.equal(css.status, 200);
  assert.match(css.headers["content-type"], /^text\/css/);
  const head = await request(new URL("assets/app.css", server.url), { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.body, "");
  assert.equal(Number(head.headers["content-length"]), Buffer.byteLength("body { color: #123; }"));

  await server.close();
  await server.close();
  await assert.rejects(request(server.url), /ECONNREFUSED|socket hang up/i);
});

test("static runtime server rejects methods, dotfiles, traversal and unknown media", async (t) => {
  const root = await fixture(t);
  const server = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
  t.after(() => server.close());

  const post = await request(server.url, { method: "POST" });
  assert.equal(post.status, 405);
  assert.equal(post.headers.allow, "GET, HEAD");
  const dotfile = await request(new URL(".env", server.url));
  assert.equal(dotfile.status, 404);
  assert.doesNotMatch(dotfile.body, /must-not-serve/);
  const traversal = await request(server.url, { rawPath: "/%2e%2e/outside.txt" });
  assert.equal(traversal.status, 404);
  assert.doesNotMatch(traversal.body, /outside/);
  const normalizedTraversal = await request(server.url, { rawPath: "/%2e%2e/index.html" });
  assert.equal(normalizedTraversal.status, 404);
  assert.doesNotMatch(normalizedTraversal.body, /Built site/);
  const unsupported = await request(new URL("data.bin", server.url));
  assert.equal(unsupported.status, 415);
});

test("static runtime server refuses linked directories and linked assets", async (t) => {
  const root = await fixture(t);
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "modular-runtime-outside-"));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await fs.writeFile(path.join(outside, "secret.txt"), "outside-secret");
  const linkedDirectory = path.join(root, "linked-dist");
  try {
    await fs.symlink(outside, linkedDirectory, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return;
    throw error;
  }
  await assert.rejects(
    startRuntimeStaticServer({ enabled: true, root, directory: "linked-dist" }),
    (error) => ["UNSAFE_STATIC_LINK", "UNSAFE_STATIC_DIRECTORY"].includes(error?.code),
  );

  const server = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
  t.after(() => server.close());
  await fs.symlink(
    outside,
    path.join(root, "dist", "linked-assets"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const linkedAsset = await request(new URL("linked-assets/secret.txt", server.url));
  assert.equal(linkedAsset.status, 404);
  assert.doesNotMatch(linkedAsset.body, /outside-secret/);
});

test("SPA fallback is explicit and serves only the validated root index", async (t) => {
  const root = await fixture(t);
  const strictServer = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
  const fallbackServer = await startRuntimeStaticServer({
    enabled: true,
    root,
    directory: "dist",
    spaFallback: true,
  });
  t.after(() => Promise.all([strictServer.close(), fallbackServer.close()]));

  assert.equal((await request(new URL("dashboard/settings", strictServer.url))).status, 404);
  const fallback = await request(new URL("dashboard/settings", fallbackServer.url));
  assert.equal(fallback.status, 200);
  assert.match(fallback.body, /Built site/);
  assert.match(fallback.headers["content-type"], /^text\/html/);
});

test("static runtime server never binds to a non-loopback interface", async (t) => {
  const root = await fixture(t);
  await assert.rejects(
    startRuntimeStaticServer({ enabled: true, root, directory: "dist", host: "0.0.0.0" }),
    (error) => error?.code === "UNSAFE_STATIC_HOST",
  );
});
