# syntax=docker/dockerfile:1
# linux/amd64 is the verified deployment target; no cross-platform image is claimed.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go build -trimpath -ldflags='-s -w' -o /out/lupetto ./cmd/lupetto \
    && go build -trimpath -ldflags='-s -w' -o /out/lupetto-explorer ./cmd/lupetto-explorer
# Cosign 3.1.3 is not present in the observed Wolfi index. Use the upstream
# release binary, checked against its pinned release-checksums SHA-256.
RUN test "$(go env GOARCH)" = amd64 \
    && wget -O /out/cosign https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 \
    && echo '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71  /out/cosign' | sha256sum -c - \
    && chmod 0755 /out/cosign

FROM cgr.dev/chainguard/wolfi-base@sha256:c902a861151182e4ce2de29b8632ba3f7d75b68c35880580f16e353819e524d3
RUN echo 'https://packages.wolfi.dev/os' > /etc/apk/repositories \
    && apk add --no-cache apko=1.4.5-r0 docker-cli=28.5.0-r0 ca-certificates-bundle \
    && mkdir -p /var/cache/lupetto/home /var/lib/lupetto /etc/lupetto/docker /etc/lupetto/products \
    && chown -R 65532:65532 /var/cache/lupetto /var/lib/lupetto \
    && chmod 0700 /var/cache/lupetto /var/cache/lupetto/home /var/lib/lupetto
COPY --from=build /out/lupetto /out/lupetto-explorer /out/cosign /usr/local/bin/
# Regenerable caches live under XDG_CACHE_HOME; durable build workspaces and
# evidence live under XDG_DATA_HOME (<data>/lupetto/builds). Mount both.
ENV HOME=/var/cache/lupetto/home \
    XDG_CACHE_HOME=/var/cache/lupetto \
    XDG_DATA_HOME=/var/lib/lupetto \
    DOCKER_CONFIG=/etc/lupetto/docker
USER 65532:65532
WORKDIR /var/cache/lupetto
VOLUME ["/var/cache/lupetto", "/var/lib/lupetto"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/lupetto-explorer"]
CMD ["--listen", "0.0.0.0:8080", "--products", "/etc/lupetto/products/products.yaml"]
