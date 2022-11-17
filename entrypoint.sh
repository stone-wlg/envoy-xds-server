#!/usr/bin/env sh

XDS_SERVER_CONFIG=${XDS_SERVER_CONFIG:-"/opt/envoy-xds-server/config.yaml"}

/opt/envoy-xds-server/envoy-xds-server --configFile ${XDS_SERVER_CONFIG}