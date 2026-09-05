#!/bin/bash

# RBAC Migration Runner Script using golang-migrate
# This script runs all SQL migrations using the migrate tool

set -e

DB_FILE="${1:-keyorix.db}"
MIGRATIONS_DIR="migrations"

# Reject path traversal and anything but a plain filename/relative path made of
# safe characters before it gets interpolated into the migrate tool's database
# URL -- an unvalidated $1 here could otherwise be used to point the tool at an
# arbitrary path outside the intended working directory.
if [[ "$DB_FILE" == *".."* ]]; then
    echo "❌ Invalid database file path: $DB_FILE (must not contain '..')"
    exit 1
fi
if [[ ! "$DB_FILE" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "❌ Invalid database file path: $DB_FILE (only letters, digits, '.', '_', '-', '/' are allowed)"
    exit 1
fi

DATABASE_URL="sqlite3://$DB_FILE"

echo "🚀 Running RBAC migrations on database: $DB_FILE"

# Check if migrate tool is installed
MIGRATE_CMD="migrate"
if ! command -v migrate &> /dev/null; then
    # Try to find migrate in common Go bin locations
    if [[ -f "$HOME/go/bin/migrate" ]]; then
        MIGRATE_CMD="$HOME/go/bin/migrate"
    elif [[ -f "$(go env GOPATH)/bin/migrate" ]]; then
        MIGRATE_CMD="$(go env GOPATH)/bin/migrate"
    else
        echo "❌ golang-migrate tool not found!"
        echo "📦 Install it with: go install -tags 'sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
        exit 1
    fi
fi

# Check if migrations directory exists
if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    echo "❌ Migrations directory $MIGRATIONS_DIR not found!"
    exit 1
fi

# Run migrations up
echo "📄 Applying migrations..."
if $MIGRATE_CMD -path "$MIGRATIONS_DIR" -database "$DATABASE_URL" up; then
    echo "✅ All migrations applied successfully!"
else
    echo "❌ Migration failed!"
    exit 1
fi

# Show current migration version
echo ""
echo "📋 Current migration version:"
$MIGRATE_CMD -path "$MIGRATIONS_DIR" -database "$DATABASE_URL" version

echo ""
echo "🎉 Migration process completed!"