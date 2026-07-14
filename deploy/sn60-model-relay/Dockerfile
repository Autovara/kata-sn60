# SN60 model-pinning relay.
#
# The relay is a single, dependency-free stdlib module, so the image needs
# nothing but a Python runtime and that one file. Build from the kata-sn60 repo root:
#
#   docker build -f deploy/sn60-model-relay/Dockerfile -t kata-sn60-model-relay .
FROM python:3.12-slim

WORKDIR /app
COPY kata_sn60/validator_system/model_relay.py /app/sn60_model_relay.py

# Overridable at `docker run` time with -e.
ENV KATA_RELAY_HOST=0.0.0.0 \
    KATA_RELAY_PORT=8000 \
    KATA_RELAY_UPSTREAM=http://bitsec_proxy:8000 \
    KATA_RELAY_PINNED_MODEL=qwen/qwen3.6-35b-a3b \
    KATA_RELAY_AGENT_CALL_BUDGET=3 \
    KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET=150000 \
    KATA_RELAY_AGENT_TOKEN_BUDGET=24000 \
    KATA_RELAY_MAX_OUTPUT_TOKENS=32000

EXPOSE 8000
CMD ["python", "/app/sn60_model_relay.py"]
