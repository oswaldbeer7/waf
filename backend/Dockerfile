# Multi-stage build for Go backend
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Verify dependencies are downloaded
RUN go mod verify

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -o waf-backend .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite

# Create app directory
WORKDIR /app

# Copy binary and data directory
COPY --from=builder /app/waf-backend .
COPY --from=builder /app/data ./data

# Create logs directory
RUN mkdir -p /app/logs

# Expose port
EXPOSE 8080

# Set environment variables
ENV DB_PATH=/app/data/waf.db
ENV CADDY_ADMIN_API=http://caddy:2019
ENV LOG_LEVEL=info

# Run the application
CMD ["./waf-backend"]
