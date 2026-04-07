#!/bin/bash

# Keyorix Project Cleanup Script
# This script removes binary executables, build artifacts, and temporary files

set -e

echo "🧹 Starting Keyorix Project Cleanup"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to safely remove files/directories
safe_remove() {
    local path="$1"
    local description="$2"
    
    if [ -e "$path" ]; then
        rm -rf "$path"
        log_success "Removed $description: $path"
        return 0
    else
        log_info "Not found (already clean): $path"
        return 1
    fi
}

# Function to find and remove files by pattern
find_and_remove() {
    local pattern="$1"
    local description="$2"
    local found=0
    
    log_info "Looking for $description..."
    
    # Find files matching pattern (excluding .git and node_modules)
    while IFS= read -r -d '' file; do
        if [[ "$file" != *"/.git/"* ]] && [[ "$file" != *"/node_modules/"* ]] && [[ "$file" != *"/.kiro/"* ]]; then
            rm -f "$file"
            log_success "Removed $description: $file"
            ((found++))
        fi
    done < <(find . -name "$pattern" -type f -print0 2>/dev/null || true)
    
    if [ $found -eq 0 ]; then
        log_info "No $description found"
    else
        log_success "Removed $found $description file(s)"
    fi
}

echo ""
log_info "🗑️  Removing Binary Executables"
echo "================================"

# Remove main binary executables
safe_remove "./keyorix" "main CLI binary"
safe_remove "./keyorix-server" "main server binary"
safe_remove "./keyorix-test" "test binary"
safe_remove "./server/keyorix-server" "server binary"
safe_remove "./cmd/keyorix" "CLI binary"
safe_remove "./cmd/keyorix-server" "server binary"

# Find and remove any other keyorix binaries
find_and_remove "keyorix" "binary executables"
find_and_remove "keyorix-*" "binary executables with prefix"

echo ""
log_info "🗄️  Removing Database Files"
echo "============================"

# Remove database files
safe_remove "./keyorix.db" "main database file"
safe_remove "./data/keyorix.db" "data directory database"
safe_remove "./server/keyorix.db" "server database"
safe_remove "./test-keyorix.db" "test database"

# Find and remove other database files
find_and_remove "*.db" "database files"
find_and_remove "*.db-shm" "SQLite shared memory files"
find_and_remove "*.db-wal" "SQLite WAL files"

echo ""
log_info "📝 Removing Log Files"
echo "====================="

# Remove log files
safe_remove "./keyorix.log" "main log file"
safe_remove "./logs/" "logs directory"
safe_remove "./server/logs/" "server logs directory"

# Find and remove log files
find_and_remove "*.log" "log files"
find_and_remove "*.log.*" "rotated log files"

echo ""
log_info "🔑 Removing Key and Certificate Files"
echo "====================================="

# Remove key and certificate files (keep templates)
safe_remove "./keys/" "keys directory"
safe_remove "./certs/" "certificates directory"
safe_remove "./server/keys/" "server keys directory"
safe_remove "./server/certs/" "server certificates directory"

# Find and remove key/cert files
find_and_remove "*.key" "private key files"
find_and_remove "*.crt" "certificate files"
find_and_remove "*.pem" "PEM files"
find_and_remove "*.p12" "PKCS12 files"

echo ""
log_info "🏗️  Removing Build Artifacts"
echo "============================"

# Remove Go build artifacts
safe_remove "./dist/" "distribution directory"
safe_remove "./build/" "build directory"
safe_remove "./bin/" "binary directory"

# Remove test artifacts
safe_remove "./coverage.out" "Go coverage file"
safe_remove "./coverage.html" "Go coverage HTML"
safe_remove "./profile.out" "Go profile file"

# Find and remove build artifacts
find_and_remove "*.out" "Go output files"
find_and_remove "*.test" "Go test binaries"
find_and_remove "*.prof" "Go profile files"

echo ""
log_info "📦 Removing Package Manager Artifacts"
echo "====================================="

# Remove Node.js artifacts (but keep package-lock.json)
safe_remove "./web/node_modules/" "web node_modules"
safe_remove "./web/dist/" "web build output"
safe_remove "./web/.next/" "Next.js build cache"
safe_remove "./web/.nuxt/" "Nuxt.js build cache"

# Remove other package manager artifacts
find_and_remove ".DS_Store" "macOS metadata files"
find_and_remove "Thumbs.db" "Windows thumbnail cache"
find_and_remove "*.tmp" "temporary files"
find_and_remove "*.temp" "temporary files"

echo ""
log_info "🧪 Removing Test Artifacts"
echo "=========================="

# Remove test artifacts
safe_remove "./test-results/" "test results directory"
safe_remove "./playwright-report/" "Playwright test reports"
safe_remove "./web/playwright-report/" "web Playwright reports"
safe_remove "./web/test-results/" "web test results"

# Find and remove test artifacts
find_and_remove "*.test.js" "JavaScript test files"
find_and_remove "*.spec.js" "JavaScript spec files"

echo ""
log_info "🐳 Removing Docker Artifacts"
echo "============================"

# Remove Docker artifacts
safe_remove "./docker-compose.override.yml" "Docker Compose override"
safe_remove "./.env.local" "local environment file"
safe_remove "./.env.development" "development environment file"

echo ""
log_info "📋 Removing Configuration Artifacts"
echo "==================================="

# Remove generated/temporary config files (keep templates)
safe_remove "./test-config.yaml" "test configuration"
safe_remove "./config.yaml" "temporary config"
safe_remove "./keyorix-config.yaml" "temporary config"

echo ""
log_info "🔍 Removing IDE and Editor Files"
echo "================================"

# Remove IDE files
safe_remove "./.vscode/settings.json" "VS Code settings (keep workspace)"
safe_remove "./.idea/" "IntelliJ IDEA files"
safe_remove "./*.swp" "Vim swap files"
safe_remove "./*.swo" "Vim swap files"

# Find and remove editor artifacts
find_and_remove "*.swp" "Vim swap files"
find_and_remove "*.swo" "Vim swap files"
find_and_remove "*~" "backup files"

echo ""
log_info "🧹 Final Cleanup"
echo "================"

# Remove empty directories
log_info "Removing empty directories..."
find . -type d -empty -not -path "./.git/*" -not -path "./node_modules/*" -not -path "./.kiro/*" -delete 2>/dev/null || true

# Clean up any remaining artifacts
find_and_remove "core" "Go core dump files"
find_and_remove "*.orig" "merge conflict backup files"
find_and_remove "*.rej" "patch reject files"

echo ""
log_info "📊 Cleanup Summary"
echo "=================="

# Show current directory size
if command -v du &> /dev/null; then
    CURRENT_SIZE=$(du -sh . 2>/dev/null | cut -f1)
    log_info "Current project size: $CURRENT_SIZE"
fi

# Show remaining files that might be artifacts
log_info "Checking for remaining potential artifacts..."
REMAINING=$(find . -type f \( -name "keyorix*" -o -name "*.db" -o -name "*.log" \) -not -path "./.git/*" -not -path "./node_modules/*" -not -path "./.kiro/*" 2>/dev/null | head -10)

if [ -n "$REMAINING" ]; then
    log_warning "Found potential remaining artifacts:"
    echo "$REMAINING"
    echo ""
    log_warning "Review these files manually if they should be removed"
else
    log_success "No obvious artifacts remaining"
fi

echo ""
log_success "🎉 Project cleanup completed!"
log_info "The project is now clean of binary executables and build artifacts"
log_info "Run 'git status' to see what was cleaned up"

# Suggest next steps
echo ""
log_info "💡 Suggested next steps:"
echo "  1. Run 'git status' to review changes"
echo "  2. Run 'git add -A && git commit -m \"Clean up binary executables and build artifacts\"'"
echo "  3. Consider running './scripts/test-web-integration.sh' to rebuild and test"