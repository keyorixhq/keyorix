# Build stage
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
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
# The sync agent has no HTTP listener; health is managed by the Kubernetes
# controller lifecycle. HEALTHCHECK NONE makes this explicit.
HEALTHCHECK NONE
ENTRYPOINT ["keyorix-k8s-sync"]
