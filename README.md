# Docker Registry Proxy Worker

Cloudflare Worker for proxying Docker Registry v2 requests to Docker Hub and GHCR.

## Local development

```bash
npm install
npm run dev
```

## Deploy

1. Create a KV namespace and update `wrangler.toml`:

```bash
npx wrangler kv namespace create AUTH_KV
npx wrangler kv namespace create AUTH_KV --preview
```

2. Set the TOTP secret used by `/admin`:

```bash
npx wrangler secret put TOTP_SECRET
```

3. Deploy:

```bash
npm run deploy
```

The Worker also supports `WHITELIST_KV` as a legacy fallback binding.
