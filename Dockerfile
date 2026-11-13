# Central server and assessment worker image. Agents run on hosts, not in containers:
# a containerized agent would inventory the container instead of the host.
FROM rust:1.100-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY examples examples
RUN cargo build --release --locked

FROM alpine:3.22
COPY --from=build /src/target/release/software-inventory-exporter /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/software-inventory-exporter"]
