#!/bin/bash
set -e

echo "=== Schema installation ==="

mkdir -p migrations
mkdir -p internal/storage/models

cp migrations/001_init.sql migrations/
cp internal/storage/models/models.go internal/storage/models/

echo "Done."
