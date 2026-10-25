#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

docker build --platform linux/amd64 --target genhash -t ruutti-genhash .
docker run --rm -it ruutti-genhash
