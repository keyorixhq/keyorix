#!/bin/bash

# Project Rename Script: Keyorix → Keyorix
# Comprehensive renaming of project name, binaries, and all references

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

echo "🔄 Project Rename: Keyorix → Keyorix"
echo "====================================="

# Confirmation prompt
read -p "This will rename the entire project from 'Keyorix' to 'Keyorix'. Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Rename cancelled."
    exit 0
fi

# Track changes
CHANGED_FILES=0
RENAMED_FILES=0

# Function to replace text in file
replace_in_file() {
    local file="$1"
    local old_pattern="$2"
    local new_pattern="$3"
    
    if [ -f "$file" ]; then
        if grep -q "$old_pattern" "$file" 2>/dev/null; then
            sed -i.bak "s/$old_pattern/$new_pattern/g" "$file"
            rm -f "$file.bak"
            CHANGED_FILES=$((CHANGED_FILES + 1))
            log_success "Updated: $file"
            return 0
        fi
    fi
    return 1
}

# Function to rename file
rename_file() {
    local old_name="$1"
    local new_name="$2"
    
    if [ -f "$old_name" ]; then
        mv "$old_name" "$new_name"
        RENAMED_FILES=$((RENAMED_FILES + 1))
        log_success "Renamed: $old_name → $new_name"
        return 0
    elif [ -L "$old_name" ]; then
        # Handle symlinks
        rm "$old_name"
        ln -sf "bin/keyorix" keyorix 2>/dev/null || true
        ln -sf "bin/keyorix-server" keyorix-server 2>/dev/null || true
        RENAMED_FILES=$((RENAMED_FILES + 1))
        log_success "Updated symlink: $old_name → $new_name"
        return 0
    fi
    return 1
}

# 1. Update Go module name
log_info "Updating Go module name..."
if [ -f "go.mod" ]; then
    replace_in_file "go.mod" "module keyorix" "module keyorix"
    replace_in_file "go.mod" "module github.com/.*/keyorix" "module github.com/your-org/keyorix"
fi

# 2. Update main.go and cmd directory
log_info "Updating main application files..."
if [ -d "cmd/keyorix" ]; then
    mv "cmd/keyorix" "cmd/keyorix"
    log_success "Renamed: cmd/keyorix → cmd/keyorix"
    RENAMED_FILES=$((RENAMED_FILES + 1))
fi

# 3. Update configuration files
log_info "Updating configuration files..."
rename_file "keyorix-simple.yaml" "keyorix-simple.yaml"
rename_file "keyorix.yaml" "keyorix.yaml"
rename_file "keyorix.db" "keyorix.db"

# 4. Update all Go source files
log_info "Updating Go source files..."
find . -name "*.go" -type f | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
    replace_in_file "$file" "KEYORIX" "KEYORIX"
done

# 5. Update scripts
log_info "Updating scripts..."
find scripts/ -name "*.sh" -type f | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
    replace_in_file "$file" "KEYORIX" "KEYORIX"
done

# 6. Update Docker and deployment files
log_info "Updating Docker and deployment files..."
find . -name "docker-compose*.yml" -o -name "Dockerfile*" | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
done

# 7. Update web application
log_info "Updating web application..."
if [ -d "web" ]; then
    find web/ -name "*.json" -o -name "*.js" -o -name "*.ts" -o -name "*.tsx" -o -name "*.html" -o -name "*.md" | while read -r file; do
        replace_in_file "$file" "keyorix" "keyorix"
        replace_in_file "$file" "Keyorix" "Keyorix"
        replace_in_file "$file" "KEYORIX" "KEYORIX"
    done
fi

# 8. Update documentation
log_info "Updating documentation..."
find . -name "*.md" -type f | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
    replace_in_file "$file" "KEYORIX" "KEYORIX"
done

# 9. Update server configuration
log_info "Updating server configuration..."
find server/ -name "*.yaml" -o -name "*.yml" -o -name "*.json" | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
done

# 10. Update Makefile
log_info "Updating Makefile..."
if [ -f "Makefile" ]; then
    replace_in_file "Makefile" "keyorix" "keyorix"
    replace_in_file "Makefile" "Keyorix" "Keyorix"
    replace_in_file "Makefile" "KEYORIX" "KEYORIX"
fi

# 11. Update build scripts to use new binary names
log_info "Updating build scripts for new binary names..."
find scripts/ -name "*.sh" -type f | while read -r file; do
    sed -i.bak 's/bin\/keyorix/bin\/keyorix/g' "$file"
    sed -i.bak 's/bin\/keyorix-server/bin\/keyorix-server/g' "$file"
    rm -f "$file.bak"
done

# 12. Update package.json if it exists
log_info "Updating package.json..."
if [ -f "web/package.json" ]; then
    replace_in_file "web/package.json" "keyorix" "keyorix"
    replace_in_file "web/package.json" "Keyorix" "Keyorix"
fi

# 13. Update OpenAPI/Swagger documentation
log_info "Updating API documentation..."
if [ -f "server/openapi.yaml" ]; then
    replace_in_file "server/openapi.yaml" "keyorix" "keyorix"
    replace_in_file "server/openapi.yaml" "Keyorix" "Keyorix"
fi

# 14. Update migration files
log_info "Updating database migrations..."
find migrations/ -name "*.sql" | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
done

# 15. Update test files
log_info "Updating test files..."
find . -name "*_test.go" -o -name "*.test.ts" -o -name "*.test.tsx" -o -name "*.spec.ts" | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
done

# 16. Update .gitignore
log_info "Updating .gitignore..."
if [ -f ".gitignore" ]; then
    replace_in_file ".gitignore" "keyorix" "keyorix"
    replace_in_file ".gitignore" "Keyorix" "Keyorix"
fi

# 17. Rename existing binaries and symlinks
log_info "Renaming existing binaries and symlinks..."
rename_file "keyorix" "keyorix"
rename_file "keyorix-server" "keyorix-server"

# Update symlinks if they exist
if [ -L "keyorix" ]; then
    rm "keyorix"
    ln -sf "bin/keyorix" keyorix
    log_success "Updated symlink: keyorix → keyorix"
fi

if [ -L "keyorix-server" ]; then
    rm "keyorix-server"
    ln -sf "bin/keyorix-server" keyorix-server
    log_success "Updated symlink: keyorix-server → keyorix-server"
fi

# 18. Rename binaries in bin directory
log_info "Renaming binaries in bin directory..."
if [ -d "bin" ]; then
    rename_file "bin/keyorix" "bin/keyorix"
    rename_file "bin/keyorix-server" "bin/keyorix-server"
fi

# 19. Update environment variables and constants
log_info "Updating environment variables..."
find . -name "*.go" -o -name "*.sh" -o -name "*.yaml" -o -name "*.yml" | while read -r file; do
    replace_in_file "$file" "KEYORIX_" "KEYORIX_"
done

# 20. Update README and main documentation
log_info "Creating updated README..."
if [ -f "README.md" ]; then
    # Update title and main references
    sed -i.bak '1s/.*/# Keyorix - Enterprise Secret Management/' README.md
    rm -f README.md.bak
fi

# 21. Update web application title and branding
log_info "Updating web application branding..."
if [ -f "web/public/index.html" ]; then
    replace_in_file "web/public/index.html" "Keyorix" "Keyorix"
fi

if [ -f "web/src/constants.ts" ]; then
    replace_in_file "web/src/constants.ts" "Keyorix" "Keyorix"
    replace_in_file "web/src/constants.ts" "keyorix" "keyorix"
fi

# 22. Update Docker image names in build scripts
log_info "Updating Docker image names..."
find scripts/ -name "*.sh" | while read -r file; do
    replace_in_file "$file" "keyorix-" "keyorix-"
    replace_in_file "$file" "IMAGE_NAME=.*keyorix" "IMAGE_NAME=keyorix"
done

# 23. Update any remaining references in config files
log_info "Final cleanup of configuration files..."
find . -name "*.conf" -o -name "*.ini" -o -name "*.toml" | while read -r file; do
    replace_in_file "$file" "keyorix" "keyorix"
    replace_in_file "$file" "Keyorix" "Keyorix"
done

# 24. Create new build info
log_info "Updating build information..."
if [ -f "bin/build-info.txt" ]; then
    replace_in_file "bin/build-info.txt" "Keyorix" "Keyorix"
fi

# 25. Update any log files or data references
log_info "Updating log and data file references..."
find . -name "*.log" | while read -r file; do
    if [ -f "$file" ]; then
        replace_in_file "$file" "keyorix" "keyorix" 2>/dev/null || true
    fi
done

# Summary
echo ""
log_success "Project rename completed successfully!"
echo ""
echo "📊 Rename Summary:"
echo "=================="
echo "✅ Files modified: $CHANGED_FILES"
echo "✅ Files renamed: $RENAMED_FILES"
echo ""
echo "🔄 Key Changes:"
echo "==============="
echo "• Project name: Keyorix → Keyorix"
echo "• CLI binary: keyorix → keyorix"
echo "• Server binary: keyorix-server → keyorix-server"
echo "• Config files: keyorix-simple.yaml → keyorix-simple.yaml"
echo "• Database: keyorix.db → keyorix.db"
echo "• Go module: keyorix → keyorix"
echo "• Environment variables: KEYORIX_* → KEYORIX_*"
echo "• Docker images: keyorix-* → keyorix-*"
echo ""
echo "🔧 Next Steps:"
echo "=============="
echo "1. Rebuild the project:"
echo "   make clean"
echo "   make build"
echo ""
echo "2. Test the renamed binaries:"
echo "   ./bin/keyorix --help"
echo "   ./bin/keyorix-server --help"
echo ""
echo "3. Update any external references:"
echo "   - Git repository name"
echo "   - Documentation links"
echo "   - CI/CD configurations"
echo "   - Domain names or URLs"
echo ""
echo "4. Commit the changes:"
echo "   git add ."
echo "   git commit -m 'Rename project from Keyorix to Keyorix'"
echo ""
log_success "Welcome to Keyorix! 🎉"
echo ""
echo "Your enterprise secret management platform is now branded as Keyorix!"