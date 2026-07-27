import test from "node:test";
import assert from "node:assert/strict";
import { __test } from "../api/relay.js";

const restricted = {
  allowedHosts: ["example.com", "*.example.org"],
  allowAnyPublicHost: false
};

test("blocks private and local addresses", () => {
  for (const value of ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fc00::1"]) {
    assert.equal(__test.blockedIp(value), true, value);
  }
  assert.equal(__test.blockedIp("8.8.8.8"), false);
});

test("host allowlist supports exact and wildcard subdomains", () => {
  assert.equal(__test.hostAllowed("example.com", restricted), true);
  assert.equal(__test.hostAllowed("api.example.org", restricted), true);
  assert.equal(__test.hostAllowed("example.org", restricted), false);
  assert.equal(__test.hostAllowed("evil.example.net", restricted), false);
});

test("target parser blocks unsupported protocols, credentials, and ports", () => {
  assert.throws(() => __test.parseTarget("file:///etc/passwd", restricted));
  assert.throws(() => __test.parseTarget("https://user:pass@example.com/", restricted));
  assert.throws(() => __test.parseTarget("https://example.com:8443/", restricted));
  assert.equal(__test.parseTarget("https://example.com/path", restricted).hostname, "example.com");
});

test("unsafe request headers are removed", () => {
  const result = __test.cleanRequestHeaders({
    Accept: "application/json",
    Host: "internal",
    Cookie: "secret",
    "Content-Type": "application/json"
  });
  assert.deepEqual(result, {
    accept: "application/json",
    "content-type": "application/json"
  });
});

test("request body limits are enforced", () => {
  assert.equal(__test.decodeBody({ body: "abc" }, 3).toString(), "abc");
  assert.throws(() => __test.decodeBody({ body: "abcd" }, 3));
  assert.throws(() => __test.decodeBody({ body: "a", bodyBase64: "Yg==" }, 10));
});

test("timing-safe text comparison has correct semantics", () => {
  assert.equal(__test.timingSafeEqualText("abc", "abc"), true);
  assert.equal(__test.timingSafeEqualText("abc", "abd"), false);
  assert.equal(__test.timingSafeEqualText("abc", "ab"), false);
});
