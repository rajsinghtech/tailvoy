FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o grpc-echo .

FROM alpine:3.21
COPY --from=builder /app/grpc-echo /usr/local/bin/grpc-echo
ENTRYPOINT ["grpc-echo"]
