# Keyorix web dashboard

The Keyorix frontend (React + Vite + TypeScript). Served as the
`ghcr.io/keyorixhq/keyorix-web` image, and embedded into the server binary via
[`server/webui`](../server/webui) for single-binary deployments
(`make build-ui`, see [`../RELEASING.md`](../RELEASING.md)).

## Run locally

```bash
pnpm install
pnpm dev            # http://localhost:3000, proxies /api /auth /system /health to :8080
```

Start the backend separately first (`make run` from the repo root) — the dev
server proxies API calls to it, it doesn't embed one.

See [`package.json`](package.json) for the full script list (lint, test,
test:coverage, test:e2e, build) and [`vite.config.ts`](vite.config.ts) for the
dev server/build configuration.

## More context

- [`../README.md`](../README.md) — product overview
- [`../RELEASING.md`](../RELEASING.md) — how this and the server image get published
- [`CLAUDE.md`](CLAUDE.md) — frontend-specific dev conventions

<!-- CI verification commit, see PR: confirms web-only PRs skip the Go pipeline. Safe to ignore/revert. -->
