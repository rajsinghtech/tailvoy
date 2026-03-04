FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /tailvoy ./cmd/tailvoy/

FROM envoyproxy/envoy:distroless-v1.37.0

COPY --from=builder /tailvoy /usr/local/bin/tailvoy

# tailvoy wraps envoy — it starts tsnet, the ext_authz server,
# then launches envoy as a subprocess with the provided args
ENTRYPOINT ["/usr/local/bin/tailvoy"]
