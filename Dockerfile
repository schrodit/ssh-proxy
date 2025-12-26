# Build stage
FROM golang:1.25 AS builder

RUN apt-get update && apt-get install -y git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o ssh-proxy .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /app/ssh-proxy /ssh-proxy

EXPOSE 2222

CMD ["/ssh-proxy", "-config", "/config.yaml"]
