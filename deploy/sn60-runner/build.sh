#!/usr/bin/env bash
# Build (and optionally push) the SN60 sealed-room runner image = kata-tee-runner base + the SN60
# profile. The generic base already contains the reviewed, subnet-neutral inference gateway.
#
# Usage:
#   BASE=registry/kata-tee-runner@sha256:<digest> ./build.sh v9
#   BASE=registry/kata-tee-runner@sha256:<digest> ./build.sh v9 --push
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
BASE="${BASE:?set BASE to the immutable kata-tee-runner image digest}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-sn60-runner:${TAG}}"
case "$BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

case "${2:-}" in
  ""|--push) ;;
  *) echo "ERROR: usage: ./build.sh <tag> [--push]" >&2; exit 1 ;;
esac

docker build --build-arg BASE="$BASE" -t "$IMAGE" .
echo "built $IMAGE (FROM $BASE)"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"
