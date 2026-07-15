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
RUN set -- \
    "-X github.com/keyorixhq/keyorix/internal/cli.version=${VERSION}" \
    "-X github.com/keyorixhq/keyorix/internal/version.Version=${VERSION}" \
    "-X github.com/keyorixhq/keyorix/internal/version.Commit=${GIT_COMMIT}" && \
    CGO_ENABLED=0 go build -ldflags "$*" \
    -trimpath -o /out/keyorix-k8s-sync ./cmd/keyorix-k8s-sync

# Runtime stage — distroless static, non-root (no shell, no package manager). The agent
# reaches the Keyorix server over HTTPS (CA bundle baked into the static base) and the
# Kubernetes API via the mounted ServiceAccount CA; it needs no shell/wget at runtime.
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
COPY --from=builder /out/keyorix-k8s-sync /usr/local/bin/keyorix-k8s-sync
USER 65532:65532
ENTRYPOINT ["keyorix-k8s-sync"]
