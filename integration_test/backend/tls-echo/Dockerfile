FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN go mod init tls-echo && go mod tidy
COPY main.go .
RUN CGO_ENABLED=0 go build -o tls-echo .

FROM alpine:3.23
COPY --from=builder /app/tls-echo /usr/local/bin/tls-echo
ENTRYPOINT ["tls-echo"]
