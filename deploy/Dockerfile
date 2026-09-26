# Multi-stage build: compile the ACP binaries, then ship them on a slim runtime.
FROM rust:1.90-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release \
    -p acp-server -p acp-gateway -p acp-cli -p acp-agent \
    --bin mock-mcp-server

FROM debian:12-slim
RUN useradd -r -u 10001 acp
COPY --from=build /src/target/release/acp-server /usr/local/bin/
COPY --from=build /src/target/release/acp-gateway /usr/local/bin/
COPY --from=build /src/target/release/acp-cli /usr/local/bin/
COPY --from=build /src/target/release/acp-agent /usr/local/bin/
COPY --from=build /src/target/release/mock-mcp-server /usr/local/bin/
USER acp
# Default to the control-plane server; compose overrides `command` per service.
ENTRYPOINT ["acp-server"]
