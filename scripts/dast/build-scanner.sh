#!/usr/bin/env bash
# Build the combined keyorix-scanner image (ZAP + Nuclei) and prune build cache.
# Run this once after cloning the rig, and again only when bumping tool versions.
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"

echo "→ Building keyorix-scanner:latest (ZAP + Nuclei)..."
docker build -f "$WORKDIR/Dockerfile.scanner" -t keyorix-scanner:latest "$WORKDIR"

echo "→ Pruning build cache..."
docker builder prune -f

SIZE=$(docker image inspect keyorix-scanner:latest --format '{{.Size}}')
echo "✅ keyorix-scanner ready — $(numfmt --to=iec "$SIZE")"

# Ensure results dir is writable by the zap user (UID 1000) inside the container.
mkdir -p "$WORKDIR/results"
chmod 777 "$WORKDIR/results"
