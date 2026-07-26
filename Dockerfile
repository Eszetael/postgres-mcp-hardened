# ── builder ──
# Pinned, not floating: `rust:1-slim` moves, so the image could be built from a different compiler
# and different dependencies than the binaries CI tested.
FROM rust:1.83-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# --locked: the image must resolve the same dependency versions the tests ran against. Without it
# the container is built from a lockfile-free resolution nobody verified.
RUN cargo build --locked --release

# ── runtime: distroless, non-root, minimalna powierzchnia ──
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/postgres-mcp-hardened /usr/local/bin/mcp
USER nonroot
EXPOSE 8080
ENV MCP_ADDR=0.0.0.0:8080
ENTRYPOINT ["/usr/local/bin/mcp"]
