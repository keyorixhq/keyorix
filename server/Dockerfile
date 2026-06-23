# Build stage
FROM golang:1.26-alpine AS builder
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
RUN go build -ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=${VERSION} -X github.com/keyorixhq/keyorix/internal/version.Version=${VERSION} -X github.com/keyorixhq/keyorix/internal/version.Commit=${GIT_COMMIT}" \
    -o bin/keyorix-server ./server

# Runtime stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1001 keyorix && \
    adduser -D -s /bin/sh -u 1001 -G keyorix keyorix
WORKDIR /app
COPY --from=builder /app/bin/keyorix-server .
COPY --from=builder /app/server/entrypoint.sh .
RUN chmod +x entrypoint.sh
RUN mkdir -p data keys && chown -R keyorix:keyorix /app
USER keyorix
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
CMD ["./entrypoint.sh"]
