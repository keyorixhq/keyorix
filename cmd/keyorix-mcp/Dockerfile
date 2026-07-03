# Build stage
FROM golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.version=${VERSION}" \
    -trimpath -o /out/keyorix-mcp ./cmd/keyorix-mcp

# Runtime stage — minimal, non-root. ca-certificates lets the server reach the Keyorix
# API over HTTPS. The MCP server speaks JSON-RPC over stdio, so there is no exposed port.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1001 keyorix && adduser -D -s /bin/sh -u 1001 -G keyorix keyorix
COPY --from=builder /out/keyorix-mcp /usr/local/bin/keyorix-mcp
USER keyorix
ENTRYPOINT ["keyorix-mcp"]
