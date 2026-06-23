# Build stage. Build context is the operator/ module directory (a separate Go module
# from the main repo, so controller-runtime/client-go stay out of the server build).
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/keyorix-operator ./cmd

# Runtime stage — distroless static, non-root. The operator reaches the Keyorix server
# over HTTPS (ca-certificates baked into the static base) and the Kubernetes API via the
# mounted ServiceAccount CA.
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/keyorix-operator /usr/local/bin/keyorix-operator
USER 65532:65532
ENTRYPOINT ["keyorix-operator"]
