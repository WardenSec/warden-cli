# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o warden ./cmd/cli

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates git

WORKDIR /app
COPY --from=builder /app/warden /usr/local/bin/warden

ENTRYPOINT ["warden"]
CMD ["--help"]
