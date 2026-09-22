FROM rust:1.70-slim as builder

WORKDIR /build

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/av-service /usr/local/bin/av-service

# Create non-root user
RUN useradd -m -u 1000 cybershield
USER cybershield

EXPOSE 3001

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/v1/status || exit 1

CMD ["av-service"]
