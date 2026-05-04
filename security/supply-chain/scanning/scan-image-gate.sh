#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-ghcr.io/yuvalpinto/secubernetes-demo:latest}"

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache:/root/.cache" \
  aquasec/trivy:latest \
  image \
  --severity CRITICAL \
  --exit-code 1 \
  "$IMAGE"
