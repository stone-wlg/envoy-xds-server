FROM golang:1.19.3-alpine AS base

ENV GOPROXY="https://proxy.golang.com.cn,direct"

COPY . /tmp/envoy-xds-server
RUN cd /tmp/envoy-xds-server && \
  go build -o ./bin/envoy-xds-server ./cmd/envoy-xds-server/main.go

FROM golang:1.19.3-alpine

COPY --from=base /tmp/envoy-xds-server/bin/envoy-xds-server /opt/envoy-xds-server/envoy-xds-server
COPY ./config.yaml /opt/envoy-xds-server/config.yaml
COPY ./entrypoint.sh /entrypoint.sh
WORKDIR /opt/envoy-xds-server

ENTRYPOINT [ "sh", "-c", "/entrypoint.sh" ]