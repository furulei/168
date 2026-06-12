# IP168 JS Worker

Generic open-source Cloudflare Worker package for the IP168 JS version.

This repository must not contain deployment-specific Cloudflare account IDs, KV namespace IDs, custom domains, API tokens, GitHub tokens, or real admin passwords.

## Files

- `ip168-online.clean.js`: Worker backend, VLESS/WebSocket, subscription output, KV storage, and short admin APIs.
- `ip168-remote-admin-1c71e482.html`: admin page asset. Upload it to KV key `ym:index.html`.
- `wrangler.example.jsonc`: deployment template. Copy it to `wrangler.jsonc` locally before deployment.
- `.dev.vars.example`: local development secret template.
- `tests/`: source-level regression and leak checks.

## Runtime Bindings

- KV binding: `KV`
- Required secret: `ADMIN`
- Optional admin entry override: `admin_n`
- Default admin entry: `/a`
- Compatibility admin entry: `/admin`
- Subscription entry: `/sub`

`ADMIN` is the admin password. `admin_n` is only the admin path alias, not a second admin password.

## Optional Settings

- `SUB_CONVERTER_URL`: Clash/Sing-box converter service URL. If omitted, normal and base64 subscriptions still work, but converted subscriptions return a clear configuration error.
- `PROXYIP_CATALOG_SUMMARY_URL`: optional proxy catalog summary JSON URL.
- `PROXYIP_CATALOG_IPV4_URL`: optional IPv4 proxy catalog JSON URL.
- `PROXYIP_CATALOG_IPV6_URL`: optional IPv6 proxy catalog JSON URL.
- `PROXYIP_CATALOG_QUERY_URL`: optional query API URL for proxy candidates.

The proxy catalog is disabled by default in the open-source package. Deployers must provide their own catalog URLs if they want automatic proxy candidate selection.

## Local Checks

```bash
npm install
npm run check
npm test
```

## Deployment Template

```bash
copy wrangler.example.jsonc wrangler.jsonc
```

Then edit `wrangler.jsonc` locally with your Worker name and KV namespace ID. Keep `wrangler.jsonc` uncommitted.

Upload the admin page after configuring Wrangler:

```bash
npm run cf:page
```

Deploy:

```bash
npm run cf:deploy
```
