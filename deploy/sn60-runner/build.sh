#!/usr/bin/env bash
# Build (and optionally push) the SN60 sealed-room runner image = kata-tee-runner base + the SN60
# profile. The generic base already contains the reviewed, subnet-neutral inference gateway. Phala
# rooms use amd64, so the build platform is explicit even on a different host architecture.
#
# Usage:
#   BASE=registry/kata-tee-runner@sha256:<digest> ./build.sh v9
#   BASE=registry/kata-tee-runner@sha256:<digest> ./build.sh v9 --push
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
BASE="${BASE:?set BASE to the immutable kata-tee-runner image digest}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-sn60-runner:${TAG}}"
PLATFORM="${PLATFORM:-linux/amd64}"
case "$BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

case "${2:-}" in
  ""|--push) ;;
  *) echo "ERROR: usage: ./build.sh <tag> [--push]" >&2; exit 1 ;;
esac

case "$PLATFORM" in
  linux/amd64) ;;
  *) echo "ERROR: PLATFORM must be linux/amd64 for Phala rooms" >&2; exit 1 ;;
esac

build_args=(
  --platform "$PLATFORM"
  --build-arg "BASE=$BASE"
  -t "$IMAGE"
)
if [ "${2:-}" = "--push" ]; then
  docker buildx build "${build_args[@]}" --push .
else
  docker buildx build "${build_args[@]}" --load .
fi
echo "built $IMAGE (FROM $BASE)"
