# bench/tools/cedar.Dockerfile
# Pinned Cedar CLI for the expressiveness benchmark (built locally, never pushed).
# rust 1.89 is the oldest toolchain that builds cedar-policy-cli 4.15.0 (its rust-version; 1.85 fails).
# Base images are pinned by the index digests the recorded build resolved (2026-11-19).
FROM rust:1.89-slim-bookworm@sha256:d7fc7de78bb8c1469933aeecbf801314d30d7d6e9f0578bba4cfa285bfa37fe6 AS build
RUN cargo install cedar-policy-cli --version 4.15.0 --locked

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=build /usr/local/cargo/bin/cedar /usr/local/bin/cedar
ENTRYPOINT ["/usr/local/bin/cedar"]
