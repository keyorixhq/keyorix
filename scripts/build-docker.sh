#!/bin/bash

# Docker Build Script
# Builds Docker images for the Keyorix project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

echo "🐳 Docker Build for Keyorix"
echo "============================"

# Configuration
IMAGE_NAME="${IMAGE_NAME:-keyorix}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

echo "Image Name: $IMAGE_NAME"
echo "Image Tag: $IMAGE_TAG"
echo "Registry: ${REGISTRY:-'(local)'}"
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Git Commit: $GIT_COMMIT"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

# Build server Docker image
log_info "Building server Docker image..."
if [ -f "server/Dockerfile" ]; then
    FULL_IMAGE_NAME="$IMAGE_NAME-server:$IMAGE_TAG"
    if [ -n "$REGISTRY" ]; then
        FULL_IMAGE_NAME="$REGISTRY/$FULL_IMAGE_NAME"
    fi
    
    docker build \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_TIME="$BUILD_TIME" \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        -t "$FULL_IMAGE_NAME" \
        -f server/Dockerfile \
        .
    
    log_success "Server image built: $FULL_IMAGE_NAME"
else
    log_warning "server/Dockerfile not found, skipping server image"
fi

# Build web Docker image if web directory exists
if [ -d "web" ] && [ -f "web/Dockerfile" ]; then
    log_info "Building web Docker image..."
    FULL_WEB_IMAGE_NAME="$IMAGE_NAME-web:$IMAGE_TAG"
    if [ -n "$REGISTRY" ]; then
        FULL_WEB_IMAGE_NAME="$REGISTRY/$FULL_WEB_IMAGE_NAME"
    fi
    
    docker build \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_TIME="$BUILD_TIME" \
        -t "$FULL_WEB_IMAGE_NAME" \
        -f web/Dockerfile \
        web/
    
    log_success "Web image built: $FULL_WEB_IMAGE_NAME"
elif [ -d "web" ]; then
    log_info "Creating web Dockerfile..."
    cat > web/Dockerfile << 'EOF'
# Multi-stage build for web assets
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production image
FROM nginx:alpine

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
EOF
    
    FULL_WEB_IMAGE_NAME="$IMAGE_NAME-web:$IMAGE_TAG"
    if [ -n "$REGISTRY" ]; then
        FULL_WEB_IMAGE_NAME="$REGISTRY/$FULL_WEB_IMAGE_NAME"
    fi
    
    docker build \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_TIME="$BUILD_TIME" \
        -t "$FULL_WEB_IMAGE_NAME" \
        -f web/Dockerfile \
        web/
    
    log_success "Web image built: $FULL_WEB_IMAGE_NAME"
fi

# Build CLI Docker image
log_info "Building CLI Docker image..."
cat > Dockerfile.cli << 'EOF'
# Multi-stage build for CLI
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/keyorix ./cmd/keyorix

# Production image
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/bin/keyorix .
COPY --from=builder /app/keyorix-simple.yaml .

ENTRYPOINT ["./keyorix"]
CMD ["--help"]
EOF

FULL_CLI_IMAGE_NAME="$IMAGE_NAME-cli:$IMAGE_TAG"
if [ -n "$REGISTRY" ]; then
    FULL_CLI_IMAGE_NAME="$REGISTRY/$FULL_CLI_IMAGE_NAME"
fi

docker build \
    --build-arg VERSION="$VERSION" \
    --build-arg BUILD_TIME="$BUILD_TIME" \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    -t "$FULL_CLI_IMAGE_NAME" \
    -f Dockerfile.cli \
    .

log_success "CLI image built: $FULL_CLI_IMAGE_NAME"

# Clean up temporary Dockerfile
rm -f Dockerfile.cli

# Create docker-compose override for built images
log_info "Creating docker-compose override..."
cat > docker-compose.override.yml << EOF
version: '3.8'

services:
  keyorix:
    image: $FULL_IMAGE_NAME
    
  nginx:
    image: $FULL_WEB_IMAGE_NAME
EOF

# Display built images
echo ""
log_success "Docker build completed!"
echo ""
echo "🐳 Built Images:"
echo "==============="
docker images | grep "$IMAGE_NAME" || true
echo ""
echo "🔧 Usage:"
echo "  docker run --rm $FULL_CLI_IMAGE_NAME --help"
echo "  docker run -p 8080:8080 $FULL_IMAGE_NAME"
echo "  docker-compose up  # Uses built images"
echo ""

# Push to registry if specified
if [ -n "$REGISTRY" ] && [ "${PUSH_IMAGES:-false}" = "true" ]; then
    log_info "Pushing images to registry..."
    
    if docker push "$FULL_IMAGE_NAME"; then
        log_success "Pushed server image to registry"
    else
        log_warning "Failed to push server image"
    fi
    
    if [ -n "$FULL_WEB_IMAGE_NAME" ]; then
        if docker push "$FULL_WEB_IMAGE_NAME"; then
            log_success "Pushed web image to registry"
        else
            log_warning "Failed to push web image"
        fi
    fi
    
    if docker push "$FULL_CLI_IMAGE_NAME"; then
        log_success "Pushed CLI image to registry"
    else
        log_warning "Failed to push CLI image"
    fi
fi

log_success "All Docker images ready! 🎉"