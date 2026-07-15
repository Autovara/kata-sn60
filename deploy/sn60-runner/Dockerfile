# The SN60 sealed-room runner = the generic kata-tee-runner base + the SN60 profile.
#
# The base (kata-tee-runner) provides room/ (sealing, relay, attestation, the server) and pulls the
# problem image; this layer only adds SN60's execution profile + its stub agents and names it via
# KATA_TEE_PROFILE. Build with ./build.sh (it vendors relay.py from the SN60 relay source).
ARG BASE
FROM ${BASE}
WORKDIR /app
# SN60-specific execution: the profile (pull ghcr.io/bitsec-ai/<key>, run the agent, collect
# report.json) + the stub agents it falls back to for plumbing tests.
COPY tee_profile.py fixture_agent.py test_agent.py .
# SN60's miner-funded inference relay, vendored by the generic room build.
COPY relay.py .
# Tell the generic server which profile to load.
ENV KATA_TEE_PROFILE=tee_profile:Sn60TeeProfile
# CMD is inherited from the base: python -m room.server
