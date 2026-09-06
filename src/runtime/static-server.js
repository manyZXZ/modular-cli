import { constants as fsConstants, promises as fs } from "node:fs";
import http from "node:http";
import path from "node:path";

const DEFAULT_STARTUP_TIMEOUT_MS = 5_000;
const DEFAULT_CLOSE_TIMEOUT_MS = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const MAX_STATIC_FILE_BYTES = 64 * 1024 * 1024;

const MIME_TYPES = Object.freeze({
  ".avif": "image/avif",
  ".css": "text/css; charset=utf-8",
  ".gif": "image/gif",
  ".htm": "text/html; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".mp3": "audio/mpeg",
  ".mp4": "video/mp4",
  ".ogg": "audio/ogg",
  ".otf": "font/otf",
  ".png": "image/png",
  ".svg": "image/svg+xml; charset=utf-8",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
  ".webm": "video/webm",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".xml": "application/xml; charset=utf-8",
});

export class RuntimeStaticServerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = "RuntimeStaticServerError";
    this.code = code;
  }
}

function boundedInteger(value, fallback, name, { minimum = 1, maximum = 600_000 } = {}) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    throw new RuntimeStaticServerError(
      "INVALID_STATIC_SERVER_OPTION",
      `${name} must be an integer between ${minimum} and ${maximum}.`,
    );
  }
  return selected;
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

async function canonicalDirectory(value, label) {
  let real;
  let stat;
  try {
    real = await fs.realpath(path.resolve(String(value)));
    stat = await fs.stat(real);
  } catch (error) {
    throw new RuntimeStaticServerError("INVALID_STATIC_DIRECTORY", `${label} is not accessible.`, { cause: error });
  }
  if (!stat.isDirectory()) {
    throw new RuntimeStaticServerError("INVALID_STATIC_DIRECTORY", `${label} must be a directory.`);
  }
  return real;
}

async function assertNoLinkedComponents(parent, candidate) {
  const relative = path.relative(parent, candidate);
  if (!relative || !isWithin(parent, candidate)) {
    throw new RuntimeStaticServerError(
      "UNSAFE_STATIC_DIRECTORY",
      "The static directory must be a non-root subdirectory of the repository.",
    );
  }
  let current = parent;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) {
      throw new RuntimeStaticServerError(
        "UNSAFE_STATIC_LINK",
        "Symbolic links and junctions are not allowed in the runtime static path.",
      );
    }
  }
}

async function validateStaticRoot(root, directory) {
  const lexicalRoot = path.resolve(String(root ?? process.cwd()));
  const realRoot = await canonicalDirectory(lexicalRoot, "Runtime repository root");
  if (directory === undefined || directory === null || String(directory).trim() === "") {
    throw new RuntimeStaticServerError(
      "STATIC_DIRECTORY_REQUIRED",
      "An explicit built static directory is required; Modular will not run a build script.",
    );
  }
  const lexicalDirectory = path.resolve(lexicalRoot, String(directory));
  if (!isWithin(lexicalRoot, lexicalDirectory) || lexicalDirectory === lexicalRoot) {
    throw new RuntimeStaticServerError(
      "UNSAFE_STATIC_DIRECTORY",
      "The static directory must be a non-root subdirectory inside the repository.",
    );
  }
  await assertNoLinkedComponents(lexicalRoot, lexicalDirectory);
  const realDirectory = await canonicalDirectory(lexicalDirectory, "Runtime static directory");
  if (!isWithin(realRoot, realDirectory) || realDirectory === realRoot) {
    throw new RuntimeStaticServerError(
      "UNSAFE_STATIC_DIRECTORY",
      "The static directory resolves outside the repository.",
    );
  }
  return { root: realRoot, directory: realDirectory };
}

function responseHeaders(contentType, length) {
  return {
    "Cache-Control": "no-store",
    "Content-Length": String(length),
    "Content-Type": contentType,
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  };
}

function sendStatus(response, status, message, extraHeaders = {}) {
  const body = Buffer.from(message);
  response.writeHead(status, {
    ...responseHeaders("text/plain; charset=utf-8", body.length),
    ...extraHeaders,
  });
  response.end(body);
}

function requestSegments(requestUrl) {
  if (typeof requestUrl !== "string" || requestUrl.length > 4_096) {
    throw new RuntimeStaticServerError("INVALID_STATIC_REQUEST", "The request URL is invalid.");
  }
  let parsed;
  let decoded;
  let rawDecoded;
  try {
    rawDecoded = decodeURIComponent(requestUrl.split(/[?#]/, 1)[0]);
    parsed = new URL(requestUrl, "http://127.0.0.1");
    decoded = decodeURIComponent(parsed.pathname);
  } catch {
    throw new RuntimeStaticServerError("INVALID_STATIC_REQUEST", "The request URL is invalid.");
  }
  if (decoded.includes("\0") || decoded.includes("\\") || rawDecoded.includes("\0") || rawDecoded.includes("\\")) {
    throw new RuntimeStaticServerError("INVALID_STATIC_REQUEST", "The request path is invalid.");
  }
  const rawSegments = rawDecoded.split("/").filter(Boolean);
  if (rawSegments.some((segment) => segment === "." || segment === ".." || segment.startsWith("."))) {
    throw new RuntimeStaticServerError("INVALID_STATIC_REQUEST", "Hidden and parent paths are not served.");
  }
  const segments = decoded.split("/").filter(Boolean);
  if (segments.some((segment) => segment === "." || segment === ".." || segment.startsWith("."))) {
    throw new RuntimeStaticServerError("INVALID_STATIC_REQUEST", "Hidden and parent paths are not served.");
  }
  return { segments, directoryRequest: decoded.endsWith("/") };
}

async function assertSafeAsset(staticRoot, candidate) {
  if (!isWithin(staticRoot, candidate)) {
    throw new RuntimeStaticServerError("UNSAFE_STATIC_ASSET", "The requested asset escapes the static directory.");
  }
  const relative = path.relative(staticRoot, candidate);
  let current = staticRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) {
      throw new RuntimeStaticServerError("UNSAFE_STATIC_LINK", "Linked assets are not served.");
    }
  }
  const real = await fs.realpath(candidate);
  if (!isWithin(staticRoot, real)) {
    throw new RuntimeStaticServerError("UNSAFE_STATIC_ASSET", "The requested asset resolves outside the static directory.");
  }
  const stat = await fs.stat(real);
  if (!stat.isFile()) throw Object.assign(new Error("Not a regular file"), { code: "ENOENT" });
  if (stat.size > MAX_STATIC_FILE_BYTES) {
    throw new RuntimeStaticServerError(
      "STATIC_ASSET_TOO_LARGE",
      `The requested asset exceeds the ${MAX_STATIC_FILE_BYTES} byte runtime-server limit.`,
    );
  }
  return { real, stat };
}

async function resolveAsset(staticRoot, requestUrl, spaFallback) {
  const { segments, directoryRequest } = requestSegments(requestUrl);
  let candidate = path.join(staticRoot, ...segments);
  try {
    const initial = await fs.lstat(candidate);
    if (initial.isSymbolicLink()) {
      throw new RuntimeStaticServerError("UNSAFE_STATIC_LINK", "Linked assets are not served.");
    }
    if (initial.isDirectory() || directoryRequest) candidate = path.join(candidate, "index.html");
    const asset = await assertSafeAsset(staticRoot, candidate);
    if (initial.isDirectory() && !directoryRequest) {
      const requested = new URL(requestUrl, "http://127.0.0.1");
      // Rebuild a single-leading-slash relative path; never redirect to a
      // request-controlled authority, even for a //host/path request target.
      asset.redirect = `/${segments.map(encodeURIComponent).join("/")}/${requested.search}`;
    }
    return asset;
  } catch (error) {
    if (!spaFallback || !["ENOENT", "ENOTDIR"].includes(error?.code)) throw error;
    return assertSafeAsset(staticRoot, path.join(staticRoot, "index.html"));
  }
}

function listen(server, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      server.close(() => {});
      reject(new RuntimeStaticServerError("STATIC_SERVER_START_TIMEOUT", "The static server did not bind in time."));
    }, timeoutMs);
    const finish = (callback) => (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    server.once("error", finish((error) => reject(new RuntimeStaticServerError(
      "STATIC_SERVER_START_FAILED",
      "The loopback static server could not start.",
      { cause: error },
    ))));
    server.listen(port, host, finish(() => resolve()));
  });
}

function closeServer(server, sockets, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error && error.code !== "ERR_SERVER_NOT_RUNNING") reject(error);
      else resolve();
    };
    const timer = setTimeout(() => {
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections?.();
      finish(new RuntimeStaticServerError("STATIC_SERVER_CLOSE_TIMEOUT", "The static server did not close in time."));
    }, timeoutMs);
    server.close(finish);
    server.closeIdleConnections?.();
  });
}

/**
 * Serve an already-built directory from an ephemeral loopback HTTP server.
 * The helper never invokes a build tool, package manager, or repository script.
 */
export async function startRuntimeStaticServer({
  enabled = false,
  root = process.cwd(),
  directory,
  host = "127.0.0.1",
  port = 0,
  spaFallback = false,
  startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS,
  closeTimeoutMs = DEFAULT_CLOSE_TIMEOUT_MS,
  requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
} = {}) {
  if (enabled !== true) {
    throw new RuntimeStaticServerError(
      "RUNTIME_STATIC_OPT_IN_REQUIRED",
      "Starting the runtime static server requires explicit enabled: true opt-in.",
    );
  }
  if (!new Set(["127.0.0.1", "::1"]).has(host)) {
    throw new RuntimeStaticServerError(
      "UNSAFE_STATIC_HOST",
      "The runtime static server may bind only to 127.0.0.1 or ::1.",
    );
  }
  const selectedPort = boundedInteger(port, 0, "port", { minimum: 0, maximum: 65_535 });
  const selectedStartupTimeout = boundedInteger(startupTimeoutMs, DEFAULT_STARTUP_TIMEOUT_MS, "startupTimeoutMs");
  const selectedCloseTimeout = boundedInteger(closeTimeoutMs, DEFAULT_CLOSE_TIMEOUT_MS, "closeTimeoutMs");
  const selectedRequestTimeout = boundedInteger(requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS, "requestTimeoutMs");
  const validated = await validateStaticRoot(root, directory);
  const sockets = new Set();

  const server = http.createServer(async (request, response) => {
    response.setHeader("Connection", "close");
    if (!["GET", "HEAD"].includes(request.method)) {
      sendStatus(response, 405, "Method Not Allowed", { Allow: "GET, HEAD" });
      return;
    }
    try {
      const asset = await resolveAsset(validated.directory, request.url, spaFallback === true);
      if (asset.redirect) {
        response.writeHead(308, { Location: asset.redirect, "Content-Length": 0 });
        response.end();
        return;
      }
      const extension = path.extname(asset.real).toLowerCase();
      const contentType = MIME_TYPES[extension];
      if (!contentType) {
        sendStatus(response, 415, "Unsupported Media Type");
        return;
      }
      response.writeHead(200, responseHeaders(contentType, asset.stat.size));
      if (request.method === "HEAD") {
        response.end();
        return;
      }
      let handle;
      try {
        const noFollow = fsConstants.O_NOFOLLOW ?? 0;
        handle = await fs.open(asset.real, fsConstants.O_RDONLY | noFollow);
        const openedStat = await handle.stat();
        if (!openedStat.isFile() || openedStat.dev !== asset.stat.dev || openedStat.ino !== asset.stat.ino) {
          throw new RuntimeStaticServerError("STATIC_ASSET_CHANGED", "The requested asset changed during validation.");
        }
        const openedHandle = handle;
        const stream = openedHandle.createReadStream({ autoClose: false });
        handle = null;
        let resourceClosed = false;
        const closeOpenedHandle = () => {
          if (resourceClosed) return;
          resourceClosed = true;
          void openedHandle.close().catch(() => {});
        };
        stream.on("error", () => {
          closeOpenedHandle();
          response.destroy();
        });
        stream.on("end", closeOpenedHandle);
        response.on("close", closeOpenedHandle);
        stream.pipe(response);
      } finally {
        await handle?.close().catch(() => {});
      }
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (["ENOENT", "ENOTDIR"].includes(error?.code)) sendStatus(response, 404, "Not Found");
      else if (["INVALID_STATIC_REQUEST", "UNSAFE_STATIC_ASSET", "UNSAFE_STATIC_LINK"].includes(error?.code)) {
        sendStatus(response, 404, "Not Found");
      } else if (error?.code === "STATIC_ASSET_TOO_LARGE") sendStatus(response, 413, "Payload Too Large");
      else sendStatus(response, 500, "Internal Server Error");
    }
  });
  server.maxConnections = 32;
  server.requestTimeout = selectedRequestTimeout;
  server.headersTimeout = Math.min(selectedRequestTimeout, 5_000);
  server.keepAliveTimeout = 1_000;
  server.maxRequestsPerSocket = 100;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"));

  try {
    await listen(server, host, selectedPort, selectedStartupTimeout);
  } catch (error) {
    for (const socket of sockets) socket.destroy();
    throw error;
  }
  server.unref();
  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : selectedPort;
  const displayHost = host === "::1" ? "[::1]" : host;
  let closed = false;

  return Object.freeze({
    url: `http://${displayHost}:${actualPort}/`,
    host,
    port: actualPort,
    root: validated.directory,
    repositoryRoot: validated.root,
    spaFallback: spaFallback === true,
    repositoryScriptsExecuted: false,
    async close() {
      if (closed) return;
      closed = true;
      await closeServer(server, sockets, selectedCloseTimeout);
    },
  });
}
