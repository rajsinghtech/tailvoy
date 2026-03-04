FROM golang:1.25-alpine AS builder
WORKDIR /app
RUN go mod init tcp-echo && go mod tidy
COPY main.go .
RUN CGO_ENABLED=0 go build -o tcp-echo .

FROM alpine:3.21
COPY --from=builder /app/tcp-echo /usr/local/bin/tcp-echo
ENTRYPOINT ["tcp-echo"]
