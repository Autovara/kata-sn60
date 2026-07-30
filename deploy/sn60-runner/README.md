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

2. Build the SN60 layer from the pushed generic room digest:

   ```bash
   BASE=registry/kata-tee-runner@sha256:<approved-digest> ./build.sh v1 --push
   ```

3. Review `docker-compose.yml` before every release. It contains the literal runner digest,
   project-image digest allowlist, provider routes, and execution bounds so Phala's compose
   measurement commits to the complete public security policy. Updating any of those values
   requires editing and redeploying the manifest, then approving its new measurement.

4. Upload `docker-compose.yml` to Phala and configure only the complete credential set as
   Encrypted Secrets:

   ```dotenv
   KATA_ROOM_AUTH_SECRET=<random 32-byte secret shared with the validator>
   GHCR_TOKEN=<package-read token used inside the room>
   DSTACK_DOCKER_REGISTRY=ghcr.io
   DSTACK_DOCKER_USERNAME=<registry username>
   DSTACK_DOCKER_PASSWORD=<package-read token used by the pre-launch image pull>
   ```

   Phala's pre-launch script consumes the `DSTACK_DOCKER_*` credentials to pull the private outer
   runner image. The running room consumes `GHCR_TOKEN` to pull approved private problem images.
   The two logins happen at different stages and may use the same least-privilege package-read
   token. Encrypted Secret updates replace the entire set, so always submit all five entries
   together. Never put these credential values in the Compose manifest or repository.

5. In Phala, allow gateway port `8080` and use its HTTPS endpoint as `KATA_SN60_ROOM_URL`. The
   Compose file deliberately exposes `8080:8080` for this external validator-to-room connection.
   `/health` and `/pubkey` are public, while `/run` accepts only signed, short-lived, one-time HMAC
   requests using `KATA_ROOM_AUTH_SECRET`.

6. Verify the new room's quote and confirm the attested Compose manifest contains the reviewed
   literal runner and project-image digests. Allowlist its compose measurement in the validator's
   `KATA_SN60_ROOM_MEASUREMENTS`, configure the validator with an HTTPS `KATA_SN60_ROOM_URL`, and
   give both sides the same `KATA_ROOM_AUTH_SECRET`.

## Production timing contract

Use these values for one Phala room serving the active SN60 lane:

| Where | Setting | Value | Purpose |
| --- | --- | ---: | --- |
| Phala runner | `KATA_INFERENCE_GATEWAY_TIMEOUT` | `180` | Maximum wall-clock time for one upstream provider request. |
| Miner agent source | HTTP client `timeout` | `195` | Gives the agent a small margin to receive the gateway response. |
| Phala runner | `KATA_TEE_AGENT_EXECUTION_TIMEOUT_SECONDS` | `840` | Maximum wall-clock time for the complete untrusted agent process. |
| Kata validator | `KATA_SN60_ROOM_REQUEST_LIFETIME_SECONDS` | `900` | Signed-request validity window. |
| Kata validator | `KATA_SN60_ROOM_HTTP_TIMEOUT_SECONDS` | `900` | Maximum wait for the room's HTTP response. |

The values intentionally satisfy `180 < 195 < 840 < 900`. They are infrastructure safety limits,
not a policy on model selection, tokens, number of calls, retries, or miner spending. An agent may
make any miner-funded calls, but it must complete all of them within its 840-second total process
budget. The signed-request lifetime is checked when the room accepts the request; it is not an
execution timer. Keep the problem images warm in the room so image pulling does not consume the
HTTP response margin.

For miner inference, the miner verifies `/pubkey`'s room attestation, then uses the generic
`kata_seal.py` tool to encrypt `{provider, api_key, bundle_binding}` to that public key. The binding
covers the submission files other than the ciphertext itself, so a validator cannot pair public
ciphertext with a substituted agent to reveal the key. The miner commits only the ciphertext as
`sealed_inference_key`; the owner and validator never receive the plaintext API key or provider
descriptor. The initial public baseline has no ciphertext because it intentionally makes no funded
inference calls. For scored participants, a missing, stale, undecryptable, or bundle-mismatched
ciphertext produces a quote-bound credential-failure report; the validator scores only that
participant zero and continues the duel. The room never falls back to a platform key.

`/run` accepts only signed, short-lived, one-time requests. Its quote binds the report, candidate
bundle hash, profile/image/inference-policy provenance, project, and nonce. `POST /pull-test` is disabled by
default and can be enabled only as a signed diagnostic.
