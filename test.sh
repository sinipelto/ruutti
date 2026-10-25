#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

account="${1:-testi}"

docker build --platform linux/amd64 -t ruutti .
docker run --rm -it ruutti "$account"
