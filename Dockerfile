# syntax = docker/dockerfile:experimental
FROM rust:1.44.1-slim-buster

RUN apt update && apt autoremove -y && apt upgrade -y
RUN apt install -y procps iproute2 iputils-ping net-tools binutils debootstrap

WORKDIR /app/toy-container
# RUN mkdir -p /app/toy-container
COPY . /app/toy-container
ENV CARGO_BUILD_TARGET_DIR /tmp/target

# RUN cd /app/toy-container/ && cargo build --bin main
RUN cargo build --bin main
ENV RUST_BACKTRACE full
ENTRYPOINT ["cargo", "run", "--bin"]
#ENTRYPOINT ["bash", "-c", "'cd /app/toy-container/ && cargo run --bin'"]
