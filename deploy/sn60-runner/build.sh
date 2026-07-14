#!/usr/bin/env bash
# Build (and optionally push) the SN60 sealed-room runner image = kata-tee-runner base + the SN60
# profile. Vendors relay.py from the SN60 relay source of truth so it never goes stale.
#
# Usage:
#   ./build.sh v9                       # build tag v9 on the default base
#   ./build.sh v9 --push                # build + push
#   BASE=kata-tee-runner:v3 ./build.sh v9   # pin the base image
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
BASE="${BASE:-kata-tee-runner:latest}"
IMAGE="docker.io/carloscosimano/kata-sn60-runner:${TAG}"

# The relay's source of truth (see ../../KATA-TEE-RUNNER-PLAN.md §6). Vendored, never edited here.
RELAY_SRC="../../kata_sn60/validator_system/model_relay.py"
[ -f "$RELAY_SRC" ] || { echo "ERROR: relay source not found at $RELAY_SRC" >&2; exit 1; }
cp "$RELAY_SRC" relay.py
echo "vendored relay.py <- $RELAY_SRC"

docker build --build-arg BASE="$BASE" -t "$IMAGE" .
echo "built $IMAGE (FROM $BASE)"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"
