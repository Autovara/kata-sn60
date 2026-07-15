# SN60 sealed runner deployment

This image is the SN60 profile on top of the generic `kata-tee-runner` room. It executes an
untrusted candidate only on the room's internal Docker network, and its inference gateway receives a
candidate-provided key for each job. There is no validator or deploy-time inference-key fallback.

1. Build the generic room with an immutable Python base:

   ```bash
   (cd ../../../kata-tee-runner && \
     PYTHON_BASE=python:3.12-slim@sha256:<approved-digest> ./build.sh v1 --push)
   ```

2. Build the SN60 layer from the pushed generic room digest, then deploy the final pushed image by
   its digest (not the `v1`/`vN` tag):

   ```bash
   BASE=registry/kata-tee-runner@sha256:<approved-digest> ./build.sh v1 --push
   export KATA_SN60_RUNNER_IMAGE=registry/kata-sn60-runner@sha256:<approved-digest>
   ```

3. In Phala, deliver `KATA_ROOM_AUTH_SECRET`, `GHCR_USER`, and `GHCR_TOKEN` as sealed secrets.
   Set `KATA_SN60_TEE_IMAGE_DIGESTS_JSON` to a JSON object mapping every permitted Bitsec project
   key to its GHCR `sha256:<digest>`. Configure the gateway upstream/provider routes:
   `KATA_INFERENCE_GATEWAY_UPSTREAM` for an OpenAI-compatible proxy route, or
   `KATA_INFERENCE_GATEWAY_DIRECT_KEY_PREFIXES` plus
   `KATA_INFERENCE_GATEWAY_DIRECT_UPSTREAM` for another OpenAI-compatible provider. The gateway
   forwards the miner's own key and requested model, sampling, token, and call settings unchanged.

4. Set `KATA_ROOM_BIND_ADDRESS` to a private validator-reachable address. Keep the default loopback
   binding for local testing. Do not expose port 8080 to the internet; HMAC authentication is a
   second control, not a replacement for network isolation.

5. Allowlist the final image's TEE measurement in the validator's
   `KATA_SN60_ROOM_MEASUREMENTS`, configure the validator with an HTTPS `KATA_SN60_ROOM_URL`, and
   give both sides the same `KATA_ROOM_AUTH_SECRET`.

For a miner key, the miner verifies `/pubkey`'s room attestation, seals their provider API key to
that public key, and commits the ciphertext as `sealed_inference_key` with their submission. The
initial public baseline has no ciphertext because it intentionally makes no funded inference calls;
an agent without a ciphertext receives an empty credential, never a platform key. The gateway rejects
an inference request without a miner key before it can reach any provider.

`/run` accepts only signed, short-lived, one-time requests. Its quote binds the report, candidate
bundle hash, profile/image/inference-policy provenance, project, and nonce. `POST /pull-test` is disabled by
default and can be enabled only as a signed diagnostic.
