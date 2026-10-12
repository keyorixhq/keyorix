# Build stage
FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -trimpath -o /out/keyorix-mcp ./cmd/keyorix-mcp

# Runtime stage — distroless static, non-root (no shell, no package manager). The MCP
# server speaks JSON-RPC over stdio (no exposed port) and reaches the Keyorix API over
# HTTPS using the CA bundle baked into the static base; it needs no shell/wget at runtime.
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
COPY --from=builder /out/keyorix-mcp /usr/local/bin/keyorix-mcp
USER 65532:65532
# MCP server communicates over stdio; no HTTP port is exposed so a CMD-based
# health probe is not applicable. HEALTHCHECK NONE makes this explicit.
HEALTHCHECK NONE
ENTRYPOINT ["keyorix-mcp"]
