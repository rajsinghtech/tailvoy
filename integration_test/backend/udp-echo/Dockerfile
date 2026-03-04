FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN go mod init udp-echo && go mod tidy
COPY main.go .
RUN CGO_ENABLED=0 go build -o udp-echo .

FROM alpine:3.21
COPY --from=builder /app/udp-echo /usr/local/bin/udp-echo
ENTRYPOINT ["udp-echo"]
