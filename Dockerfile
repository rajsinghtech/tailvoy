FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w" -o /tailvoy ./cmd/tailvoy/

FROM envoyproxy/envoy:distroless-v1.37.2

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="tailvoy"
LABEL org.opencontainers.image.description="Tailscale identity-aware firewall for Envoy"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.source="https://github.com/rajsinghtech/tailvoy"

COPY --from=builder /tailvoy /usr/local/bin/tailvoy

# tsnet needs a writable home directory for state
ENV HOME=/tmp/tailvoy

# tailvoy wraps envoy — it starts tsnet, the ext_authz server,
# then launches envoy as a subprocess with the provided args
ENTRYPOINT ["/usr/local/bin/tailvoy"]
