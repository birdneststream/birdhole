# --- Build Stage --- 
FROM golang:alpine AS builder
WORKDIR /app

# Install build dependencies (like gcc for CGO if needed, though we aim to disable it)
# RUN apk add --no-cache gcc musl-dev

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 disables CGO for a static binary (usually smaller)
# -ldflags="-s -w" strips debugging information (smaller binary)
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/birdhole .

# --- Final Stage --- 
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies (tzdata for timezones, mailcap for /etc/mime.types)
# Add su-exec for dropping privileges in entrypoint
RUN apk add --no-cache tzdata mailcap 'su-exec>=0.2'

# Copy the built binary from the builder stage
COPY --from=builder /app/birdhole /app/birdhole

# Copy static assets and templates
COPY static ./static
COPY templates ./templates

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copy the default config (optional, can be fully managed via volume)
# COPY config.toml.example /app/config.toml

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create necessary directories and set permissions
# Assuming default BitcaskPath is ./birdhole.db relative to workdir
# RUN mkdir ./birdhole.db && chown -R appuser:appgroup /app
VOLUME /app/birdhole.db

# Expose the port the application listens on (based on logs)
EXPOSE 9999

# Entrypoint executes the script
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command passed to entrypoint
CMD ["/app/birdhole"] 