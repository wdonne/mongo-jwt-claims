FROM alpine:3.24.3 AS builder
ARG TARGETPLATFORM
COPY target/aarch64-unknown-linux-musl/release/mongo-jwt-claims /target/aarch64-unknown-linux-musl/release/
COPY target/x86_64-unknown-linux-musl/release/mongo-jwt-claims /target/x86_64-unknown-linux-musl/release/
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
    cp /target/aarch64-unknown-linux-musl/release/mongo-jwt-claims /mongo-jwt-claims; \
    elif [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
    cp /target/x86_64-unknown-linux-musl/release/mongo-jwt-claims /mongo-jwt-claims; \
    fi
RUN apk add ca-certificates && update-ca-certificates

FROM scratch
USER 11000:11000
COPY --from=builder /mongo-jwt-claims /app/
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
ENTRYPOINT ["/app/mongo-jwt-claims"]