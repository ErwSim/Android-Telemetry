# Watchpost collector image (build context: server/).
#
#   docker build -t watchpost-collector:local server/
#
# Behind an HTTPS proxy with a private CA (corporate or integration environments):
#   docker build --network host --build-arg HTTPS_PROXY=… \
#     --secret id=ca_bundle,src=/path/to/ca.crt -t watchpost-collector:local server/

ARG NODE_IMAGE=node:22-bookworm-slim
ARG GO_IMAGE=golang:1.24-bookworm

# --- 1. Web console (optional: without console/package.json, the fallback page is served)
FROM ${NODE_IMAGE} AS console
RUN --mount=type=bind,target=/ctx \
    --mount=type=cache,target=/root/.npm \
    --mount=type=secret,id=ca_bundle,required=false \
    set -eu; mkdir -p /out; \
    if [ -f /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi; \
    if [ -f /ctx/console/package.json ]; then \
      mkdir -p /build && cd /ctx/console && \
      tar --exclude=./node_modules --exclude=./dist -cf - . | tar -xf - -C /build && \
      cd /build && npm ci --no-audit --no-fund && npm run build && cp -r dist/. /out/; \
    else \
      echo "console/package.json missing: fallback page"; \
    fi

# --- 2. Static Go binary (no CGO)
FROM ${GO_IMAGE} AS build
ARG VERSION=dev
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src
COPY collector/go.mod collector/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=ca_bundle,required=false \
    if [ -f /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    go mod download
COPY collector/ ./
COPY --from=console /out/ /tmp/console/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; rm -rf web/dist; \
    if [ -f /tmp/console/index.html ]; then cp -r /tmp/console web/dist; fi; \
    go vet ./... && \
    go build -ldflags "-s -w -X main.version=${VERSION}" -o /rootfs/usr/local/bin/watchpost-collector . && \
    mkdir -p /rootfs/data /rootfs/export /rootfs/tmp /rootfs/etc/ssl/certs && \
    cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ && \
    printf 'root:x:0:0:root:/root:/sbin/nologin\nwatchpost:x:65532:65532:watchpost:/data:/sbin/nologin\n' > /rootfs/etc/passwd && \
    printf 'root:x:0:\nwatchpost:x:65532:\n' > /rootfs/etc/group && \
    chown 65532:65532 /rootfs/data /rootfs/export && chmod 0700 /rootfs/data && chmod 0750 /rootfs/export && chmod 1777 /rootfs/tmp

# --- 3. Minimal final image, unprivileged user
FROM scratch
COPY --from=build /rootfs/ /
USER 65532:65532
ENV WATCHPOST_DATA_DIR=/data WATCHPOST_LISTEN=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/watchpost-collector", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/watchpost-collector"]
CMD ["serve"]
