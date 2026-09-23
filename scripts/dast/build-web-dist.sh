#!/usr/bin/env bash
# Rebuilds web/dist from src/ into a throwaway node container -- run this
# after every `git -C src pull` so the DAST server keeps serving the current
# dashboard build (single-binary mode via web_assets_path in
# keyorix-dast.yaml) instead of a stale or missing one. No node/pnpm needed
# on the LXC host itself; only docker.
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")" && pwd)"

# pnpm comes from corepack, which installs exactly the version AND sha512 pinned
# in web/package.json's "packageManager" field and verifies it -- not an
# unpinned `npm install -g pnpm@x` (Scorecard PinnedDependencies). The node
# image is pinned by digest for the same reason; bump both deliberately.
docker run --rm \
  -v "$WORKDIR/src/web:/app" \
  -w /app \
  -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
  node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85 \
  sh -c 'corepack enable pnpm && pnpm install --frozen-lockfile --ignore-scripts && pnpm build'

echo "web/dist rebuilt. Run 'docker compose up -d keyorix' if the container needs recreating to pick up a fresh mount."
