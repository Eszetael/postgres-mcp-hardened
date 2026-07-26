# ── builder ──
FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# ── runtime: distroless, non-root, minimalna powierzchnia ──
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/postgres-mcp-hardened /usr/local/bin/mcp
USER nonroot
EXPOSE 8080
ENV MCP_ADDR=0.0.0.0:8080
ENTRYPOINT ["/usr/local/bin/mcp"]
