# Build stage
FROM golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Injected at build time so the agent reports its real release version (mirrors the
# Makefile LDFLAGS). Defaults keep ad-hoc `docker build` working; docker-publish
# passes the git tag + sha.
ARG VERSION=dev
ARG GIT_COMMIT=none
RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=${VERSION} -X github.com/keyorixhq/keyorix/internal/version.Version=${VERSION} -X github.com/keyorixhq/keyorix/internal/version.Commit=${GIT_COMMIT}" \
    -trimpath -o /out/keyorix-k8s-sync ./cmd/keyorix-k8s-sync

# Runtime stage — minimal, non-root. ca-certificates lets the agent reach the
# Keyorix server over HTTPS; the Kubernetes API is trusted via the mounted SA CA.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1001 keyorix && adduser -D -s /bin/sh -u 1001 -G keyorix keyorix
COPY --from=builder /out/keyorix-k8s-sync /usr/local/bin/keyorix-k8s-sync
USER keyorix
ENTRYPOINT ["keyorix-k8s-sync"]
