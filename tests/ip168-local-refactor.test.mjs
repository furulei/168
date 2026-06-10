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
  assert.ok(source.includes("/ht/dl"));
  assert.ok(source.includes("/pg/du"));
  assert.ok(source.includes("/pg/xie"));
  assert.ok(source.includes("/rk/du"));
  assert.ok(source.includes("/fd/zd/du"));
  assert.ok(source.includes("/fd/zd/ce"));
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

test("optional converter and proxy catalog defaults are empty for open-source builds", async () => {
  const source = await readSource();
  assert.ok(source.includes('var DEFAULT_SUB_CONVERTER_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_SUMMARY_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_IPV4_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_IPV6_URL = "";'));
  assert.ok(source.includes('var PROXYIP_CATALOG_QUERY_URL = "";'));
  assert.ok(source.includes("enabled: false"));
});
