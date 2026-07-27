# Build stage. Build context is the operator/ module directory (a separate Go module
# from the main repo, so controller-runtime/client-go stay out of the server build).
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/keyorix-operator ./cmd

# Runtime stage — distroless static, non-root. The operator reaches the Keyorix server
# over HTTPS (ca-certificates baked into the static base) and the Kubernetes API via the
# mounted ServiceAccount CA.
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
COPY --from=builder /out/keyorix-operator /usr/local/bin/keyorix-operator
USER 65532:65532
ENTRYPOINT ["keyorix-operator"]
