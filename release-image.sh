#!/bin/sh

set -eu

repo="mrubli/uptime-kuma"
package="ghcr.io/${repo}"
label="tls"

npm run build

docker build -f docker/dockerfile --platform linux/amd64 -t "${package}:tmp" --target release .

echo "FROM ${package}:tmp" | docker build --label "org.opencontainers.image.source=https://github.com/${repo}" -t "${package}:${label}" -

docker push "${package}:${label}"

docker rmi "${package}:tmp"
