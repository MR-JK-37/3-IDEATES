FROM rust:1.70-slim as builder

WORKDIR /build

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/av-ai /usr/local/bin/av-ai

RUN useradd -m -u 1000 cybershield
USER cybershield

EXPOSE 3003

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:3003/api/v1/status || exit 1

CMD ["av-ai"]
