# Build stage
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
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
