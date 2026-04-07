#!/bin/bash

# Simple Project Rename Script: Keyorix → Keyorix
# Safe, non-looping version

set -e

echo "🔄 Simple Project Rename: Keyorix → Keyorix"
echo "============================================="

# Confirmation
read -p "Rename project from 'Keyorix' to 'Keyorix'? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Rename cancelled."
    exit 0
fi

echo "✅ Starting rename process..."

# 1. Update go.mod
echo "📦 Updating Go module..."
if [ -f "go.mod" ]; then
    sed -i.bak 's/module keyorix/module keyorix/g' go.mod
    rm -f go.mod.bak
    echo "✅ Updated go.mod"
fi

# 2. Rename cmd directory
echo "📁 Renaming cmd directory..."
if [ -d "cmd/keyorix" ]; then
    mv "cmd/keyorix" "cmd/keyorix"
    echo "✅ Renamed cmd/keyorix → cmd/keyorix"
fi

# 3. Rename config files
echo "⚙️  Renaming configuration files..."
[ -f "keyorix-simple.yaml" ] && mv "keyorix-simple.yaml" "keyorix-simple.yaml" && echo "✅ Renamed config file"
[ -f "keyorix.yaml" ] && mv "keyorix.yaml" "keyorix.yaml" && echo "✅ Renamed yaml config"
[ -f "keyorix.db" ] && mv "keyorix.db" "keyorix.db" && echo "✅ Renamed database file"

# 4. Update main files with simple sed
echo "🔧 Updating main source files..."
for file in main.go go.mod go.sum; do
    if [ -f "$file" ]; then
        sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' -e 's/KEYORIX/KEYORIX/g' "$file"
        rm -f "$file.bak"
        echo "✅ Updated $file"
    fi
done

# 5. Update key Go files
echo "🐹 Updating Go source files..."
for dir in cmd internal server; do
    if [ -d "$dir" ]; then
        find "$dir" -name "*.go" -exec sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' -e 's/KEYORIX/KEYORIX/g' {} \;
        find "$dir" -name "*.go.bak" -delete
        echo "✅ Updated Go files in $dir"
    fi
done

# 6. Update scripts
echo "📜 Updating scripts..."
if [ -d "scripts" ]; then
    find scripts -name "*.sh" -exec sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' -e 's/KEYORIX/KEYORIX/g' {} \;
    find scripts -name "*.sh.bak" -delete
    echo "✅ Updated script files"
fi

# 7. Update Makefile
echo "🔨 Updating Makefile..."
if [ -f "Makefile" ]; then
    sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' -e 's/KEYORIX/KEYORIX/g' Makefile
    rm -f Makefile.bak
    echo "✅ Updated Makefile"
fi

# 8. Update README
echo "📖 Updating README..."
if [ -f "README.md" ]; then
    sed -i.bak -e '1s/.*/# Keyorix - Enterprise Secret Management/' -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' README.md
    rm -f README.md.bak
    echo "✅ Updated README.md"
fi

# 9. Update key documentation files
echo "📚 Updating documentation..."
for file in *.md; do
    if [ -f "$file" ]; then
        sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' -e 's/KEYORIX/KEYORIX/g' "$file"
        rm -f "$file.bak"
    fi
done
echo "✅ Updated documentation files"

# 10. Update Docker files
echo "🐳 Updating Docker configurations..."
for file in docker-compose*.yml Dockerfile*; do
    if [ -f "$file" ]; then
        sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' "$file"
        rm -f "$file.bak"
        echo "✅ Updated $file"
    fi
done

# 11. Update web files if they exist
echo "🌐 Updating web application..."
if [ -d "web" ]; then
    if [ -f "web/package.json" ]; then
        sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' web/package.json
        rm -f web/package.json.bak
        echo "✅ Updated web/package.json"
    fi
    
    # Update key web files
    for file in web/src/constants.ts web/public/index.html web/README.md; do
        if [ -f "$file" ]; then
            sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' "$file"
            rm -f "$file.bak"
            echo "✅ Updated $file"
        fi
    done
fi

# 12. Update server config
echo "⚙️  Updating server configuration..."
if [ -d "server" ]; then
    for file in server/config/*.yaml server/*.yaml; do
        if [ -f "$file" ]; then
            sed -i.bak -e 's/keyorix/keyorix/g' -e 's/Keyorix/Keyorix/g' "$file"
            rm -f "$file.bak"
        fi
    done
    echo "✅ Updated server configuration"
fi

# 13. Rename binaries and symlinks
echo "🔗 Updating binaries and symlinks..."
[ -f "keyorix" ] && mv "keyorix" "keyorix" && echo "✅ Renamed binary: keyorix → keyorix"
[ -f "keyorix-server" ] && mv "keyorix-server" "keyorix-server" && echo "✅ Renamed binary: keyorix-server → keyorix-server"

# Update symlinks
[ -L "keyorix" ] && rm "keyorix" && ln -sf "bin/keyorix" keyorix && echo "✅ Updated symlink: keyorix → keyorix"
[ -L "keyorix-server" ] && rm "keyorix-server" && ln -sf "bin/keyorix-server" keyorix-server && echo "✅ Updated symlink: keyorix-server → keyorix-server"

# Rename binaries in bin directory
if [ -d "bin" ]; then
    [ -f "bin/keyorix" ] && mv "bin/keyorix" "bin/keyorix" && echo "✅ Renamed bin/keyorix → bin/keyorix"
    [ -f "bin/keyorix-server" ] && mv "bin/keyorix-server" "bin/keyorix-server" && echo "✅ Renamed bin/keyorix-server → bin/keyorix-server"
fi

# 14. Update .gitignore
echo "📝 Updating .gitignore..."
if [ -f ".gitignore" ]; then
    sed -i.bak -e 's/keyorix/keyorix/g' .gitignore
    rm -f .gitignore.bak
    echo "✅ Updated .gitignore"
fi

echo ""
echo "🎉 Rename completed successfully!"
echo ""
echo "📊 Summary:"
echo "==========="
echo "✅ Project name: Keyorix → Keyorix"
echo "✅ CLI binary: keyorix → keyorix"
echo "✅ Server binary: keyorix-server → keyorix-server"
echo "✅ Config files: keyorix-simple.yaml → keyorix-simple.yaml"
echo "✅ Go module updated"
echo "✅ Source code updated"
echo "✅ Documentation updated"
echo "✅ Build system updated"
echo ""
echo "🔧 Next steps:"
echo "1. Rebuild: make clean && make build"
echo "2. Test: ./bin/keyorix --help"
echo "3. Commit: git add . && git commit -m 'Rename to Keyorix'"
echo ""
echo "🎊 Welcome to Keyorix!"