# --- Build stage ---
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /dlp ./cmd/dlp

# --- Runtime stage ---
FROM scratch
COPY --from=builder /dlp /dlp
COPY --from=builder /app/rules /rules
ENTRYPOINT ["/dlp"]
