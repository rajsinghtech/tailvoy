FROM golang:1.25-alpine AS builder
WORKDIR /app
RUN go mod init backend && go mod tidy
COPY main.go .
RUN CGO_ENABLED=0 go build -o backend_server .

FROM alpine:3.23
COPY --from=builder /app/backend_server /usr/local/bin/backend_server
ENTRYPOINT ["backend_server"]
