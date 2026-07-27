import crypto from "node:crypto";
import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";

const APP_NAME = "Private Web Relay";
const APP_VERSION = "2.0.0";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_REQUEST_BYTES = 512 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 3 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 4;
const DEFAULT_RATE_LIMIT = 30;
const RATE_WINDOW_MS = 60_000;

const SAFE_REQUEST_HEADERS = new Set([
  "accept",
  "accept-language",
  "authorization",
  "content-type",
  "if-modified-since",
  "if-none-match",
  "range",
  "user-agent"
]);

const SAFE_RESPONSE_HEADERS = new Set([
  "accept-ranges",
  "cache-control",
  "content-disposition",
  "content-language",
  "content-type",
  "etag",
  "expires",
  "last-modified"
]);

const buckets = new Map();

function envInt(name, fallback, minimum, maximum) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, parsed));
}

function envBool(name, fallback = false) {
  const raw = process.env[name];
  if (raw == null) return fallback;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

function getConfig() {
  return {
    apiKey: (process.env.RELAY_API_KEY || "").trim(),
    allowedHosts: (process.env.ALLOWED_HOSTS || "")
      .split(",")
      .map((value) => value.trim().toLowerCase().replace(/\.$/, ""))
      .filter(Boolean),
    allowAnyPublicHost: envBool("ALLOW_ANY_PUBLIC_HOST", false),
    allowedOrigin: (process.env.ALLOWED_ORIGIN || "").trim(),
    timeoutMs: envInt("REQUEST_TIMEOUT_MS", DEFAULT_TIMEOUT_MS, 2_000, 30_000),
    maxRequestBytes: envInt(
      "MAX_REQUEST_BYTES",
      DEFAULT_MAX_REQUEST_BYTES,
      0,
      1024 * 1024
    ),
    maxResponseBytes: envInt(
      "MAX_RESPONSE_BYTES",
      DEFAULT_MAX_RESPONSE_BYTES,
      10_000,
      3_500_000
    ),
    maxRedirects: envInt("MAX_REDIRECTS", DEFAULT_MAX_REDIRECTS, 0, 8),
    rateLimit: envInt("RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT, 1, 300)
  };
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function requestIp(request) {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return request.socket?.remoteAddress || "unknown";
}

function enforceRateLimit(identity, limit) {
  const now = Date.now();
  const existing = buckets.get(identity) || [];
  const fresh = existing.filter((timestamp) => now - timestamp < RATE_WINDOW_MS);
  if (fresh.length >= limit) {
    const error = new Error("Rate limit exceeded");
    error.statusCode = 429;
    throw error;
  }
  fresh.push(now);
  buckets.set(identity, fresh);

  if (buckets.size > 5_000) {
    for (const [key, values] of buckets.entries()) {
      if (!values.some((timestamp) => now - timestamp < RATE_WINDOW_MS)) {
        buckets.delete(key);
      }
    }
  }
}

function hostAllowed(hostname, config) {
  if (config.allowAnyPublicHost) return true;
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return config.allowedHosts.some((pattern) => {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1);
      return host.endsWith(suffix) && host !== suffix.slice(1);
    }
    return timingSafeEqualText(host, pattern);
  });
}

function blockedIp(address) {
  const version = net.isIP(address);
  if (!version) return true;

  if (version === 4) {
    const octets = address.split(".").map(Number);
    const [a, b, c] = octets;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }

  const normalized = address.toLowerCase().split("%")[0];
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    /^fe[89ab]/.test(normalized) ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8:") ||
    normalized.startsWith("2001:2:") ||
    normalized.startsWith("2001:10:")
  );
}

async function resolvePublicHost(hostname) {
  let results;
  try {
    results = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    const error = new Error("Target hostname could not be resolved");
    error.statusCode = 502;
    throw error;
  }

  if (!results.length || results.some((entry) => blockedIp(entry.address))) {
    const error = new Error("Target resolves to a blocked or non-public address");
    error.statusCode = 403;
    throw error;
  }

  return results;
}

function parseTarget(rawUrl, config) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    const error = new Error("Malformed target URL");
    error.statusCode = 400;
    throw error;
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    const error = new Error("Only HTTP and HTTPS targets are allowed");
    error.statusCode = 400;
    throw error;
  }
  if (url.username || url.password) {
    const error = new Error("Credentials inside target URLs are not allowed");
    error.statusCode = 400;
    throw error;
  }
  if (!hostAllowed(url.hostname, config)) {
    const error = new Error("Target hostname is not allowed");
    error.statusCode = 403;
    throw error;
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    const error = new Error("Only target ports 80 and 443 are allowed");
    error.statusCode = 403;
    throw error;
  }
  return url;
}

function cleanRequestHeaders(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const output = {};
  let count = 0;
  for (const [rawName, rawValue] of Object.entries(input)) {
    if (count >= 20) break;
    const name = String(rawName).trim().toLowerCase();
    const value = String(rawValue);
    if (!SAFE_REQUEST_HEADERS.has(name)) continue;
    if (value.length > 4096 || /[\r\n]/.test(value)) continue;
    output[name] = value;
    count += 1;
  }
  return output;
}

function decodeBody(payload, maxBytes) {
  if (payload.body != null && payload.bodyBase64 != null) {
    const error = new Error("Provide body or bodyBase64, not both");
    error.statusCode = 400;
    throw error;
  }

  let body = null;
  if (payload.bodyBase64 != null) {
    if (typeof payload.bodyBase64 !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(payload.bodyBase64)) {
      const error = new Error("bodyBase64 is invalid");
      error.statusCode = 400;
      throw error;
    }
    body = Buffer.from(payload.bodyBase64, "base64");
  } else if (payload.body != null) {
    body = Buffer.from(String(payload.body), "utf8");
  }

  if (body && body.length > maxBytes) {
    const error = new Error("Relay request body is too large");
    error.statusCode = 413;
    throw error;
  }
  return body;
}

function performPinnedRequest({ url, method, headers, body, addresses, timeoutMs, maxResponseBytes }) {
  return new Promise((resolve, reject) => {
    const selected = addresses[0];
    const transport = url.protocol === "https:" ? https : http;
    const options = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      path: `${url.pathname || "/"}${url.search}`,
      method,
      headers: {
        ...headers,
        host: url.host,
        connection: "close"
      },
      timeout: timeoutMs,
      lookup(_hostname, optionsOrCallback, maybeCallback) {
        const callback = typeof optionsOrCallback === "function" ? optionsOrCallback : maybeCallback;
        callback(null, selected.address, selected.family);
      }
    };

    if (url.protocol === "https:") {
      options.servername = url.hostname;
      options.rejectUnauthorized = true;
    }
    if (body) options.headers["content-length"] = String(body.length);

    const upstream = transport.request(options, (upstreamResponse) => {
      const chunks = [];
      let total = 0;
      let finished = false;

      const fail = (error) => {
        if (finished) return;
        finished = true;
        upstreamResponse.destroy();
        reject(error);
      };

      upstreamResponse.on("data", (chunk) => {
        total += chunk.length;
        if (total > maxResponseBytes) {
          const error = new Error("Upstream response exceeds configured limit");
          error.statusCode = 413;
          fail(error);
          return;
        }
        chunks.push(chunk);
      });

      upstreamResponse.on("end", () => {
        if (finished) return;
        finished = true;
        resolve({
          statusCode: upstreamResponse.statusCode || 502,
          statusMessage: upstreamResponse.statusMessage || "",
          headers: upstreamResponse.headers,
          body: Buffer.concat(chunks)
        });
      });

      upstreamResponse.on("error", fail);
    });

    upstream.on("timeout", () => {
      const error = new Error("Upstream request timed out");
      error.statusCode = 504;
      upstream.destroy(error);
    });
    upstream.on("error", (cause) => {
      if (cause.statusCode) return reject(cause);
      const error = new Error("Upstream connection failed");
      error.statusCode = 502;
      reject(error);
    });

    if (body) upstream.write(body);
    upstream.end();
  });
}

async function fetchWithValidatedRedirects(payload, config) {
  const method = String(payload.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "POST"].includes(method)) {
    const error = new Error("Method must be GET, HEAD, or POST");
    error.statusCode = 400;
    throw error;
  }

  let currentUrl = parseTarget(String(payload.url || ""), config);
  let currentMethod = method;
  let body = decodeBody(payload, config.maxRequestBytes);
  const headers = cleanRequestHeaders(payload.headers);
  headers["user-agent"] ||= `${APP_NAME}/${APP_VERSION}`;

  for (let redirect = 0; redirect <= config.maxRedirects; redirect += 1) {
    const addresses = await resolvePublicHost(currentUrl.hostname);
    const result = await performPinnedRequest({
      url: currentUrl,
      method: currentMethod,
      headers,
      body,
      addresses,
      timeoutMs: config.timeoutMs,
      maxResponseBytes: config.maxResponseBytes
    });

    const location = result.headers.location;
    const isRedirect = [301, 302, 303, 307, 308].includes(result.statusCode) && location;
    if (!isRedirect) {
      return { ...result, finalUrl: currentUrl.toString() };
    }
    if (redirect === config.maxRedirects) {
      const error = new Error("Too many redirects");
      error.statusCode = 508;
      throw error;
    }

    currentUrl = parseTarget(new URL(location, currentUrl).toString(), config);
    if ([301, 302, 303].includes(result.statusCode) && currentMethod === "POST") {
      currentMethod = "GET";
      body = null;
      delete headers["content-length"];
      delete headers["content-type"];
    }
  }

  const error = new Error("Redirect handling failed");
  error.statusCode = 502;
  throw error;
}

function setCors(request, response, config) {
  const origin = request.headers.origin;
  if (config.allowedOrigin && origin === config.allowedOrigin) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Relay-Key, Authorization");
    response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  }
}

function sendError(response, statusCode, message, requestId) {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.status(statusCode).json({ error: message, requestId });
}

export default async function handler(request, response) {
  const requestId = crypto.randomUUID();
  const config = getConfig();
  response.setHeader("X-Relay-Request-Id", requestId);
  response.setHeader("Cache-Control", "no-store");
  setCors(request, response, config);

  if (request.method === "OPTIONS") {
    return response.status(config.allowedOrigin ? 204 : 403).end();
  }
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST, OPTIONS");
    return sendError(response, 405, "Use POST /api/relay", requestId);
  }
  if (!config.apiKey) {
    return sendError(response, 503, "RELAY_API_KEY is not configured", requestId);
  }

  const authorization = String(request.headers.authorization || "");
  const bearer = authorization.toLowerCase().startsWith("bearer ")
    ? authorization.slice(7).trim()
    : "";
  const suppliedKey = String(request.headers["x-relay-key"] || bearer || "");
  if (!suppliedKey || !timingSafeEqualText(suppliedKey, config.apiKey)) {
    return sendError(response, 401, "Invalid or missing relay key", requestId);
  }

  try {
    const identity = crypto
      .createHash("sha256")
      .update(`${suppliedKey}:${requestIp(request)}`)
      .digest("hex")
      .slice(0, 24);
    enforceRateLimit(identity, config.rateLimit);

    const payload = request.body;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      const error = new Error("Request body must be JSON");
      error.statusCode = 400;
      throw error;
    }

    const result = await fetchWithValidatedRedirects(payload, config);
    response.setHeader("X-Relay-Final-Url", encodeURI(result.finalUrl).slice(0, 2048));
    response.setHeader("X-Relay-Upstream-Status", String(result.statusCode));

    for (const [name, rawValue] of Object.entries(result.headers)) {
      const lower = name.toLowerCase();
      if (!SAFE_RESPONSE_HEADERS.has(lower) || rawValue == null) continue;
      const value = Array.isArray(rawValue) ? rawValue.join(", ") : String(rawValue);
      if (!/[\r\n]/.test(value)) response.setHeader(name, value);
    }

    return response.status(result.statusCode).send(result.body);
  } catch (error) {
    const statusCode = Number.isInteger(error?.statusCode) ? error.statusCode : 500;
    const safeMessage = statusCode >= 500 && !error?.statusCode
      ? "Unexpected relay error"
      : String(error?.message || "Relay request failed");
    console.error(JSON.stringify({
      requestId,
      statusCode,
      message: safeMessage,
      type: error?.name || "Error"
    }));
    return sendError(response, statusCode, safeMessage, requestId);
  }
}

export const __test = {
  blockedIp,
  cleanRequestHeaders,
  decodeBody,
  hostAllowed,
  parseTarget,
  timingSafeEqualText
};
