# The SN60 sealed-room runner = the generic kata-tee-runner base + the SN60 profile.
#
# The generic base provides sealing, the inference gateway, attestation, and the
# room server. This layer adds only SN60's execution profile and plumbing agents.
# A fail-closed placeholder keeps accidental direct builds from selecting a
# mutable base. build.sh requires the caller to replace it with an approved
# immutable kata-tee-runner digest.
ARG BASE=example.invalid/kata-tee-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000
FROM ${BASE}
WORKDIR /app
# SN60-specific execution: the profile (pull ghcr.io/bitsec-ai/<key>, run the agent, collect
# report.json) + the stub agents it falls back to for plumbing tests.
COPY tee_profile.py fixture_agent.py test_agent.py .
# Tell the generic server which profile to load.
ENV KATA_TEE_PROFILE=tee_profile:Sn60TeeProfile
# CMD is inherited from the base: python -m room.server
