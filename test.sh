#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

docker run -it -p 18000:18000 --rm stonewlg/envoy-xds-server:1.0.0 sh
