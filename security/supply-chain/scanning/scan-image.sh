#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-ghcr.io/yuvalpinto/secubernetes-demo:latest}"
OUTPUT_DIR="docs/demo-evidence/supply-chain"
OUTPUT_FILE="$OUTPUT_DIR/trivy-scan-secubernetes-demo.txt"

mkdir -p "$OUTPUT_DIR"

echo "[trivy] scanning image: $IMAGE"

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache:/root/.cache" \
  aquasec/trivy:latest \
  image \
  --severity HIGH,CRITICAL \
  --format table \
  "$IMAGE" | tee "$OUTPUT_FILE"

echo "[trivy] scan evidence saved to $OUTPUT_FILE"
