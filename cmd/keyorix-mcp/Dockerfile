# Build stage
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
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
FROM gcr.io/distroless/static:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=builder /out/keyorix-mcp /usr/local/bin/keyorix-mcp
USER 65532:65532
# MCP server communicates over stdio; no HTTP port is exposed so a CMD-based
# health probe is not applicable. HEALTHCHECK NONE makes this explicit.
HEALTHCHECK NONE
ENTRYPOINT ["keyorix-mcp"]
