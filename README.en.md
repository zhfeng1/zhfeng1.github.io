# Docker Registry Proxy Worker

Cloudflare Worker for proxying Docker Registry v2 requests to Docker Hub and GHCR.

## Local development

```bash
npm install
npm run dev
```

## Deploy

1. Create a KV namespace and update `wrangler.toml`.
2. Set `TOTP_SECRET` with `npx wrangler secret put TOTP_SECRET`.
3. Run `npm run deploy`.
