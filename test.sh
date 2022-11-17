#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

docker run -it --rm stonewlg/envoy-xds-server:1.0.0 sh
