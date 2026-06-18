# IP168 JS Worker

Generic open-source Cloudflare Worker package for the IP168 JS version.

This repository must not contain deployment-specific Cloudflare account IDs, KV namespace IDs, API tokens, GitHub tokens, or real admin passwords. Bundled public service URLs for seed data, proxy catalogs, admin HTML, and subscription conversion are intentional defaults for single-JS deployment.

## Files

- `ip168-online.clean.js`: Worker backend, VLESS/WebSocket, subscription output, KV storage, remote admin page loading, and short admin APIs.
- `ip168-remote-admin-1c71e482.html`: admin page asset loaded by the Worker from the public repository URL.
- `wrangler.example.jsonc`: deployment template. Copy it to `wrangler.jsonc` locally before deployment.
- `.dev.vars.example`: local development secret template.
- `tests/`: source-level regression and leak checks.

## Runtime Bindings

- KV binding: `KV`
- Required secret: `ADMIN`
- Optional admin entry override: `admin_n`
- Default admin entry: `/a`
- Subscription entry: `/sub`

`ADMIN` is the admin password. `admin_n` is only the admin path alias, not a second admin password.

## Optional Settings

- `SUB_CONVERTER_URL`: Clash/Sing-box converter service URL. If omitted, Clash and Sing-box use the bundled default converter `https://sub.ip168.dpdns.org`.
- `ENTRY_SEED_URL`: optional entry seed JSON URL. If omitted, the bundled `furulei/168` seed is used.
- `PROXYIP_CATALOG_SUMMARY_URL`: optional proxy catalog summary JSON URL. If omitted, the bundled `furulei/cf` summary catalog is used.
- `PROXYIP_CATALOG_IPV4_URL`: optional IPv4 proxy catalog JSON URL. If omitted, the bundled `furulei/cf` IPv4 catalog is used.
- `PROXYIP_CATALOG_IPV6_URL`: optional IPv6 proxy catalog JSON URL. If omitted, the bundled `furulei/cf` IPv6 catalog is used.

The default seed, proxy catalog, and converter are bundled so the single JS deployment works without extra setup. Deployers can still override these URLs with environment variables.

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

Deploy:

```bash
npm run cf:deploy
```
