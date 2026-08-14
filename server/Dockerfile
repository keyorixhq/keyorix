# Build stage
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS builder
RUN apk add --no-cache git make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Injected at build time so the image reports its real release version at runtime
# (e.g. /health, /system/info). Defaults keep ad-hoc `docker build` working; the
# docker-publish workflow passes the git tag + sha. Mirrors the Makefile LDFLAGS.
ARG VERSION=dev
ARG GIT_COMMIT=none
RUN set -- \
    "-X github.com/keyorixhq/keyorix/internal/cli.version=${VERSION}" \
    "-X github.com/keyorixhq/keyorix/internal/version.Version=${VERSION}" \
    "-X github.com/keyorixhq/keyorix/internal/version.Commit=${GIT_COMMIT}" && \
    go build -ldflags "$*" \
    -o bin/keyorix-server ./server

# Runtime stage
#
# NOTE on distroless (backlog #242): entrypoint.sh needs a real shell plus `wget`,
# `mktemp`, `trap`, and `seq` for its first-boot admin-bootstrap logic (waiting for
# /health, then POSTing the initial admin via wget --post-file). distroless/static
# and distroless/base have no shell or busybox utilities at all, so a direct swap
# would break that bootstrap flow. Moving the bootstrap into the Go binary itself
# (invoked via a flag) would remove the need for the shell script entirely and let
# this image go fully distroless, but that's a larger refactor than this hardening
# round should attempt — tracked as a follow-up. In the meantime we keep Alpine but
# strip the `apk` package manager (binary + package db) once the packages we need
# are installed, so RCE inside this container can no longer `apk add` extra tooling.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates tzdata && \
    rm -rf /sbin/apk /etc/apk /lib/apk /usr/share/apk /var/cache/apk && \
    addgroup -g 1001 keyorix && \
    adduser -D -s /bin/sh -u 1001 -G keyorix keyorix
WORKDIR /app
COPY --from=builder /app/bin/keyorix-server .
COPY --from=builder /app/server/entrypoint.sh .
RUN chmod +x entrypoint.sh && \
    mkdir -p data keys && chown -R keyorix:keyorix /app
USER 1001:1001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1"]
CMD ["./entrypoint.sh"]
