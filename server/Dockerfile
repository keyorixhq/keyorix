# Build stage
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /app
COPY go.mod go.sum go.work go.work.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=dev" \
    -o bin/keyorix-server ./server/main.go

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
