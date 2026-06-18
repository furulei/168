import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";

const sourceUrl = new URL("../ip168-online.clean.js", import.meta.url);
const rootUrl = new URL("../", import.meta.url);

async function readSource() {
  return await readFile(sourceUrl, "utf8");
}

async function readText(path) {
  return await readFile(new URL(path, rootUrl), "utf8");
}

test("ip168 source switches to the new kv key names", async () => {
  const source = await readSource();
  assert.ok(source.includes('var CONFIG_KV_KEY = "pg.json";'));
  assert.ok(source.includes('var ENTRY_ENDPOINTS_KV_KEY = "rk.txt";'));
  assert.ok(source.includes('var PROXY_HEALTH_KV_KEY = "fd.jk.json";'));
  assert.ok(source.includes('var PROXY_AUTO_KV_KEY = "fd.zd.json";'));
  assert.ok(source.includes('var PROXY_AUTO_STATE_KV_KEY = "fd.zt.json";'));
  assert.ok(source.includes('var ADMIN_PAGE_KV_KEY = "ym:index.html";'));
});

test("ip168 source defaults the admin root to /a and exposes the new short routes", async () => {
  const source = await readSource();
  assert.ok(source.includes('ADMIN_ROOT: "/a"'));
  assert.ok(source.includes('ADMIN_ALIAS: "/admin"'));
  assert.ok(source.includes("/ht/dl"));
  assert.ok(source.includes("/pg/du"));
  assert.ok(source.includes("/pg/xie"));
  assert.ok(source.includes("/rk/du"));
  assert.ok(source.includes("/fd/zd/du"));
  assert.ok(source.includes("/fd/zd/ce"));
});

test("ip168 source accepts the legacy /admin alias for the admin entry", async () => {
  const source = await readSource();
  assert.ok(source.includes('const bases = [normalizePathAlias(basePath), ROUTES.ADMIN_ALIAS].filter(Boolean);'));
});

test("ip168 source removes legacy admin api routes", async () => {
  const source = await readSource();
  assert.equal(source.includes("/api/bootstrap"), false);
  assert.equal(source.includes("/api/state"), false);
  assert.equal(source.includes("/api/save"), false);
  assert.equal(source.includes("/api/entries"), false);
  assert.equal(source.includes("/api/proxy/test"), false);
  assert.equal(source.includes("/api/proxy/auto"), false);
  assert.equal(source.includes("/api/proxy/run"), false);
});

test("ip168 source removes remote admin page fallback", async () => {
  const source = await readSource();
  assert.equal(source.includes("REMOTE_ADMIN_PAGE_URL"), false);
  assert.equal(source.includes("ADMIN_PAGE_URL"), false);
  assert.equal(source.includes("fetchRemoteAdminHtml"), false);
  assert.equal(source.includes("getRemoteAdminPageUrl"), false);
});

test("repository keeps deployment-specific config out of source control", async () => {
  const files = await readdir(rootUrl);
  assert.equal(files.includes("wrangler.jsonc"), false);
  assert.equal(files.includes("wrangler.example.jsonc"), true);

  const wranglerExample = await readText("wrangler.example.jsonc");
  assert.ok(wranglerExample.includes("your-worker-name"));
  assert.ok(wranglerExample.includes("your-kv-namespace-id"));
  assert.equal(wranglerExample.includes("routes"), false);
});

test("repository does not contain known instance identifiers or secrets", async () => {
  const files = [
    "ip168-online.clean.js",
    "ip168-remote-admin-1c71e482.html",
    "README.md",
    "package.json",
    "wrangler.example.jsonc",
    ".dev.vars.example"
  ];
  const combined = (await Promise.all(files.map((file) => readText(file)))).join("\n");
  for (const pattern of [
    new RegExp(["d", "pdns"].join("") + "\\.org", "i"),
    new RegExp(["cf", "ut_"].join(""), "i"),
    new RegExp(["cf", "at_"].join(""), "i"),
    new RegExp(["github", "_pat_"].join(""), "i"),
    new RegExp(["workers", "\\.dev"].join(""), "i"),
    new RegExp(["furu", "lei"].join(""), "i"),
    new RegExp("__" + "IP168" + "_[A-Z0-9_]+")
  ]) {
    assert.equal(pattern.test(combined), false, String(pattern));
  }
});

test("ip168 source removes legacy env aliases and source comments", async () => {
  const source = await readSource();
  for (const legacy of [
    "ADMIN_PATH_ALIAS",
    "ADMIN_N",
    "admin_path_alias",
    "ENTRY_PATH_LIMIT",
    "entry_path_limit",
    "COOKIE_SECRET",
    "env?.admin ||",
    "sub_token",
    '"TOKEN", "token"',
    "env?.uuid",
    "env?.host",
    "entry_endpoints",
    "ADD_TEXT",
    "add_text",
    '"SUB_CONVERTER", "sub_converter"',
    "proxyip_catalog_",
    "@__PURE__",
    "/** @type",
    "// worker-ip168-proxy-mode.js"
  ]) {
    assert.equal(source.includes(legacy), false, legacy);
  }
  const adminHtml = await readText("ip168-remote-admin-1c71e482.html");
  assert.equal(adminHtml.includes("<!--IP168_BOOTSTRAP-->"), false);
  assert.equal(adminHtml.includes("???"), false);
  assert.equal(source.includes("<!--IP168_BOOTSTRAP-->"), false);
});

test("optional converter and proxy catalog defaults are empty for open-source builds", async () => {
  const source = await readSource();
  assert.ok(source.includes('var DEFAULT_SUB_CONVERTER_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_SUMMARY_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_IPV4_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_IPV6_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_QUERY_URL = "";'));
  assert.ok(source.includes("enabled: false"));
});

test("proxy auto normalization keeps the open-source default disabled", async () => {
  const source = await readSource();
  assert.equal(source.includes("enabled: hasCountry ? true : Boolean(input.enabled)"), false);
  assert.ok(source.includes('const hasExplicitEnabled = Object.prototype.hasOwnProperty.call(input, "enabled");'));
  assert.ok(source.includes("enabled: hasExplicitEnabled ? Boolean(input.enabled) : DEFAULT_PROXY_AUTO_SETTINGS.enabled"));
});

test("proxy probe route is not shadowed by proxy catalog route", async () => {
  const source = await readSource();
  const probeRoute = source.indexOf("if (url.pathname === adminProxyTestPath)");
  const catalogRoute = source.indexOf("if (url.pathname === adminProxyCatalogPath || url.pathname.startsWith(`${adminProxyCatalogPath}/`))");
  assert.notEqual(probeRoute, -1);
  assert.notEqual(catalogRoute, -1);
  assert.ok(probeRoute < catalogRoute);
});

test("proxy probe endpoint accepts the UI timeout range", async () => {
  const source = await readSource();
  assert.equal(source.includes("const timeoutMs = clampNumber(body.timeoutMs, 3000, 1e3, 3e3);"), false);
  assert.ok(source.includes("const timeoutMs = clampNumber(body.timeoutMs, randomProxyProbeTimeoutMs(), 1e3, 1500);"));
});

test("proxy probe matches desktop trace target and skips google requests", async () => {
  const source = await readSource();
  const adminHtml = await readText("ip168-remote-admin-1c71e482.html");
  assert.ok(source.includes('var PROXYIP_TRACE_HOST = "speed.cloudflare.com";'));
  assert.ok(source.includes("timeoutMs: 1500,"));
  assert.ok(source.includes("randomProxyProbeTimeoutMs(settings.timeoutMs)"));
  assert.ok(source.includes("const timeoutMs = clampNumber(body.timeoutMs, randomProxyProbeTimeoutMs(), 1e3, 1500);"));
  assert.ok(adminHtml.includes("const AUTO_RUN_TEST_TIMEOUT_MIN_MS = 1000;"));
  assert.ok(adminHtml.includes("const AUTO_RUN_TEST_TIMEOUT_MAX_MS = 1500;"));
  assert.ok(adminHtml.includes("timeoutMs: randomAutoRunTestTimeoutMs(),"));
  assert.equal(adminHtml.includes("googleAfterTrace: true"), false);
  assert.equal(source.includes("const google = await googleProxyEndpointCheck(endpoint, timeoutMs);"), false);
});

test("proxy probe TLS reads do not mask timeouts with releaseLock errors", async () => {
  const source = await readSource();
  assert.equal(source.includes("withTimeout(tls.read()"), false);
  assert.ok(source.includes("function safeReleaseLock(lock, label)"));
  assert.ok(source.includes('safeReleaseLock(reader, "TLS reader")'));
});

test("proxy probe treats google HTTP 4xx as reachable instead of a transport failure", async () => {
  const source = await readSource();
  assert.equal(source.includes("googleOk: status >= 200 && status < 300"), false);
  assert.ok(source.includes("googleOk: status >= 200 && status < 500"));
});

test("proxy probe availability uses cloudflare trace only", async () => {
  const source = await readSource();
  assert.equal(source.includes("if (!google.googleOk)"), false);
  assert.equal(source.includes("const google = await googleProxyEndpointCheck(endpoint, timeoutMs);"), false);
  assert.ok(source.includes("const traceOk = Boolean(trace.exitIp && trace.loc);"));
  assert.ok(source.includes("ok: traceOk,"));
  assert.ok(source.includes('error: traceOk ? null : traceError || "proxy check failed"'));
});

test("proxy probe keeps trace errors without google fallback", async () => {
  const source = await readSource();
  assert.ok(source.includes("let trace = {};"));
  assert.ok(source.includes("let traceError = null;"));
  assert.ok(source.includes('traceError = String(error?.message || error || "trace check failed").slice(0, 200);'));
  assert.equal(source.includes("const ok = Boolean(traceOk || google.googleOk);"), false);
  assert.ok(source.includes("traceError,"));
});

test("proxy probe UI uses non-google delay fields", async () => {
  const adminHtml = await readText("ip168-remote-admin-1c71e482.html");
  assert.equal(adminHtml.includes("probe.googleMs"), false);
  assert.equal(adminHtml.includes("result.googleMs"), false);
  assert.ok(adminHtml.includes("result?.traceMs ?? result?.connectMs"));
});

test("proxy probe UI does not turn auth failures into unavailable candidates", async () => {
  const adminHtml = await readText("ip168-remote-admin-1c71e482.html");
  assert.ok(adminHtml.includes("error.status = response.status;"));
  assert.ok(adminHtml.includes("isAuthError(error)"));
  assert.ok(adminHtml.includes("登录状态失效，请重新进入后台"));
  assert.ok(adminHtml.includes('throw new Error("登录状态失效，请重新进入后台");'));
});

test("proxy probe UI shows concrete probe failure reason", async () => {
  const adminHtml = await readText("ip168-remote-admin-1c71e482.html");
  assert.ok(adminHtml.includes("function probeFailureText(result)"));
  assert.ok(adminHtml.includes("result?.traceError"));
  assert.ok(adminHtml.includes("result?.googleError"));
  assert.equal(adminHtml.includes('if (!result.ok) return result.error ? "\\u4e0d\\u53ef\\u7528" : "\\u5931\\u8d25";'), false);
});
