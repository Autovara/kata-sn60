# SN60 sealed runner deployment

This image is the SN60 profile on top of the generic `kata-tee-runner` room. It executes an
untrusted candidate only on the room's internal Docker network. Its inference gateway receives a
miner-provided encrypted provider descriptor for each job. There is no validator or deploy-time
inference-key fallback.

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
   key to its GHCR `sha256:<digest>`. Configure the generic runner's provider registry with
   `KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON`. It maps reviewed provider ids to exact endpoints
   and authentication formats. For example, it may enable `openrouter`, `chutes`, and `akashml`
   simultaneously. The gateway forwards each miner's own request, model, sampling, token, and call
   settings unchanged to the route selected by that miner's encrypted descriptor. Never accept a
   miner-supplied provider URL.

4. Set `KATA_ROOM_BIND_ADDRESS` to a private validator-reachable address. Keep the default loopback
   binding for local testing. Do not expose port 8080 to the internet; HMAC authentication is a
   second control, not a replacement for network isolation.

5. Allowlist the final image's TEE measurement in the validator's
   `KATA_SN60_ROOM_MEASUREMENTS`, configure the validator with an HTTPS `KATA_SN60_ROOM_URL`, and
   give both sides the same `KATA_ROOM_AUTH_SECRET`.

For miner inference, the miner verifies `/pubkey`'s room attestation, then uses the generic
`kata_seal.py` tool to encrypt `{provider, api_key, bundle_binding}` to that public key. The binding
covers the submission files other than the ciphertext itself, so a validator cannot pair public
ciphertext with a substituted agent to reveal the key. The miner commits only the ciphertext as
`sealed_inference_key`; the owner and validator never receive the plaintext API key or provider
descriptor. The initial public baseline has no ciphertext because it intentionally makes no funded
inference calls; an agent without a ciphertext receives empty inference settings, never a platform
key. The gateway rejects an inference request without a miner key before it can reach any provider.

`/run` accepts only signed, short-lived, one-time requests. Its quote binds the report, candidate
bundle hash, profile/image/inference-policy provenance, project, and nonce. `POST /pull-test` is disabled by
default and can be enabled only as a signed diagnostic.
