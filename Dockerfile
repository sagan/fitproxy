# syntax=docker/dockerfile:1

# Stage 1: Build stage
FROM rust:alpine AS builder

WORKDIR /usr/src/fitproxy

# Install build dependencies
RUN apk add --no-cache musl-dev

# Copy manifests to cache dependency builds
COPY Cargo.toml Cargo.lock ./

# Create dummy source files to pre-build dependencies
RUN mkdir -p src && \
    echo "pub mod dummy {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/fitproxy* target/release/deps/fitproxy* target/release/deps/libfitproxy*

# Copy the actual source files and build
COPY src ./src
RUN cargo build --release && \
    strip target/release/fitproxy

# Stage 2: Runtime image
FROM alpine:latest

# Install runtime utilities for network setup (iproute2 for `ip`, nftables for `nft`)
# and ca-certificates / tzdata
RUN apk add --no-cache ca-certificates iproute2 nftables tzdata

# Copy fitproxy binary from builder stage
COPY --from=builder /usr/src/fitproxy/target/release/fitproxy /usr/local/bin/fitproxy

# Default listen ports: DNS (UDP/TCP) and TPROXY (TCP)
EXPOSE 7053/udp 7053/tcp 7080/tcp

ENTRYPOINT ["fitproxy"]
CMD ["--help"]
