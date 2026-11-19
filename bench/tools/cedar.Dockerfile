# bench/tools/cedar.Dockerfile
# Pinned Cedar CLI for the expressiveness benchmark (built locally, never pushed).
# rust 1.89 is the oldest toolchain that builds cedar-policy-cli 4.15.0 (its rust-version; 1.85 fails).
ARG RUST_VERSION=1.89
FROM rust:${RUST_VERSION}-slim-bookworm AS build
RUN cargo install cedar-policy-cli --version 4.15.0 --locked

FROM debian:bookworm-slim
COPY --from=build /usr/local/cargo/bin/cedar /usr/local/bin/cedar
ENTRYPOINT ["/usr/local/bin/cedar"]
