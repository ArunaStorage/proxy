# Build Stage
FROM harbor.computational.bio.uni-giessen.de/docker_hub_cache/library/rust:1 AS builder
WORKDIR /usr/src/
RUN apt-get update && upgrade
RUN get install llvm cmake gcc ca-certificates openssl-dev protoc libsodium libsodium-devs
COPY . .
RUN cargo build --release

FROM harbor.computational.bio.uni-giessen.de/docker_hub_cache/library/ubuntu

RUN apt-get update && upgrade
RUN apt-get install ca-certificates openssl
COPY --from=builder /usr/src/target/release/aos_data_proxy .
COPY .env .
CMD [ "./aos_data_proxy" ]