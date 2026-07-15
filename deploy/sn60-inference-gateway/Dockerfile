# SN60 miner-funded inference gateway.
#
# It is a small dependency-free network boundary: agents can reach only this
# gateway, while it forwards their unchanged requests and credentials to their
# configured provider route. Build from the kata-sn60 repository root:
#   docker build -f deploy/sn60-inference-gateway/Dockerfile -t kata-sn60-inference-gateway .
FROM python:3.12-slim

WORKDIR /app
COPY kata_sn60/validator_system/inference_gateway.py /app/sn60_inference_gateway.py

ENV KATA_INFERENCE_GATEWAY_HOST=0.0.0.0 \
    KATA_INFERENCE_GATEWAY_PORT=8000 \
    KATA_INFERENCE_GATEWAY_UPSTREAM=http://bitsec_proxy:8000

EXPOSE 8000
CMD ["python", "/app/sn60_inference_gateway.py"]
