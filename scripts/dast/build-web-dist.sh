#!/usr/bin/env bash
# Rebuilds web/dist from src/ into a throwaway node container -- run this
# after every `git -C src pull` so the DAST server keeps serving the current
# dashboard build (single-binary mode via web_assets_path in
# keyorix-dast.yaml) instead of a stale or missing one. No node/pnpm needed
# on the LXC host itself; only docker.
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")" && pwd)"

docker run --rm \
  -v "$WORKDIR/src/web:/app" \
  -w /app \
  node:22-alpine \
  sh -c 'npm install -g pnpm@11.19.0 --ignore-scripts && pnpm install --frozen-lockfile --ignore-scripts && pnpm build'

echo "web/dist rebuilt. Run 'docker compose up -d keyorix' if the container needs recreating to pick up a fresh mount."
