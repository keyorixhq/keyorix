# Build stage. Build context is the operator/ module directory (a separate Go module
# from the main repo, so controller-runtime/client-go stay out of the server build).
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/keyorix-operator ./cmd

# Runtime stage — distroless static, non-root. The operator reaches the Keyorix server
# over HTTPS (ca-certificates baked into the static base) and the Kubernetes API via the
# mounted ServiceAccount CA.
FROM gcr.io/distroless/static:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=builder /out/keyorix-operator /usr/local/bin/keyorix-operator
USER 65532:65532
ENTRYPOINT ["keyorix-operator"]
