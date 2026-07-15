#!/usr/bin/env bash
# Build (and optionally push) the SN60 sealed-room runner image = kata-tee-runner base + the SN60
# profile. Vendors the inference gateway from the SN60 source of truth so it never goes stale.
#
# Usage:
#   BASE=registry/kata-tee-runner@sha256:<digest> ./build.sh v9
#   BASE=registry/kata-tee-runner@sha256:<digest> ./build.sh v9 --push
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
BASE="${BASE:?set BASE to the immutable kata-tee-runner image digest}"
IMAGE="docker.io/carloscosimano/kata-sn60-runner:${TAG}"
case "$BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

# The gateway source of truth. Vendored, never edited here.
GATEWAY_SRC="../../kata_sn60/validator_system/inference_gateway.py"
[ -f "$GATEWAY_SRC" ] || { echo "ERROR: gateway source not found at $GATEWAY_SRC" >&2; exit 1; }
cp "$GATEWAY_SRC" inference_gateway.py
echo "vendored inference_gateway.py <- $GATEWAY_SRC"

docker build --build-arg BASE="$BASE" -t "$IMAGE" .
echo "built $IMAGE (FROM $BASE)"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"
