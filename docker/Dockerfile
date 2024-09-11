# Use an existing docker image as a base
FROM rust:latest AS builder

ARG LIGHT_CLIENT=aptos

# Install git
RUN apt-get update && apt-get install -y git build-essential pkg-config libssl-dev libudev-dev cmake clang

# Configure git to use the GitHub token for authentication
RUN --mount=type=secret,id=github_token \
    git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf ssh://git@github.com && \
    git config --global url."https://$(cat /run/secrets/github_token)@github.com".insteadOf https://github.com

# Install rust nightly
RUN rustup install nightly

# Set context in /tmp
WORKDIR /tmp

# Download Go
RUN wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz

# Install Go
RUN tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz

# Set PATH environment variable
ENV PATH=$PATH:/usr/local/go/bin

# Set workdir to /app
WORKDIR /app

# Clone Sphinx
RUN git clone https://github.com/lurk-lab/sphinx.git

# Set context in sphinx/cli
WORKDIR /app/sphinx/cli

# Install wp1 & succint toolchain
RUN cargo install --locked --force --path .
RUN cargo prove install-toolchain

# Set context in /app/aptos
WORKDIR /app/$LIGHT_CLIENT

# Copy light client folder
COPY ./$LIGHT_CLIENT .

# Determine the package name based on the value of LIGHT_CLIENT
RUN if [ "$LIGHT_CLIENT" = "aptos" ]; then \
        PACKAGE_NAME="proof-server"; \
    else \
        PACKAGE_NAME="ethereum-lc"; \
    fi && \
    RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native" cargo +nightly build --release --bins -p $PACKAGE_NAME

# Start a new stage from scratch
FROM debian:stable-slim

ARG LIGHT_CLIENT=aptos

# Install SSL libraries
RUN apt update && apt install -y openssl libssl-dev

# Set workdir to /app
WORKDIR /app

# Copy only the binaries from the builder stage
COPY --from=builder /app/$LIGHT_CLIENT/target/release/proof_server ./

# Create group and user
RUN groupadd execgroup && useradd -m -g execgroup execuser

# Give ownership of files in /app to execuser
RUN chown -R execuser:execgroup /app

# Switch to execuser
USER execuser

