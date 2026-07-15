"""Miner-funded inference gateway for sealed SN60 execution.

Untrusted miner agents run on an internal Docker network with no public egress.
They can reach this gateway at ``<INFERENCE_API>/inference``; the gateway forwards
the request to a configured inference-provider route using the miner's own API key.
It is intentionally a network boundary, not an inference policy engine:

* it never chooses or rewrites a model;
* it never changes sampling, token, call, or retry settings;
* it never measures, budgets, or pays for miner inference.

Only ``POST /inference`` (or the per-job ``POST /j/<id>/inference`` alias) can
leave the sealed agent network. This prevents arbitrary public-internet access
while allowing miners to use their own provider credentials.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

DEFAULT_UPSTREAM = "http://bitsec_proxy:8000"
DEFAULT_AKASH_UPSTREAM = "https://api.akashml.com/v1/chat/completions"
DEFAULT_TIMEOUT_SECONDS = 900

UPSTREAM_ENV = "KATA_INFERENCE_GATEWAY_UPSTREAM"
TIMEOUT_ENV = "KATA_INFERENCE_GATEWAY_TIMEOUT"
DIRECT_KEY_PREFIXES_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_KEY_PREFIXES"
DIRECT_ALLOW_UNKNOWN_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_ALLOW_UNKNOWN"
DIRECT_UPSTREAM_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_UPSTREAM"
DIRECT_AUTH_HEADER_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_AUTH_HEADER"
DIRECT_AUTH_VALUE_TEMPLATE_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_AUTH_VALUE_TEMPLATE"
AKASH_UPSTREAM_ENV = "KATA_INFERENCE_GATEWAY_AKASH_UPSTREAM"

PROXY_KEY_PREFIXES = ("sk-or-", "cpk_")
AKASH_KEY_PREFIXES = ("akml-", "akml_")
DEFAULT_DIRECT_AUTH_HEADER = "Authorization"
DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE = "Bearer {api_key}"

INFERENCE_PATH = "/inference"
HEALTH_PATH = "/healthz"
_JOB_INFERENCE_PATH = re.compile(r"/j/[^/?]{1,256}/inference\Z")

_SKIP_REQUEST_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
_SKIP_RESPONSE_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


class GatewayConfigurationError(Exception):
    """A configured direct-provider route is incomplete or invalid."""


@dataclass(frozen=True)
class DirectProviderRoute:
    """A provider endpoint and the header used to give it the miner API key."""

    upstream: str
    auth_header: str = DEFAULT_DIRECT_AUTH_HEADER
    auth_value_template: str = DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str | None) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _key_matches(api_key: str | None, prefixes: tuple[str, ...] | list[str]) -> bool:
    if not api_key:
        return False
    value = api_key.strip()
    return any(prefix == "*" or value.startswith(prefix) for prefix in prefixes)


def is_proxy_provider_key(api_key: str | None) -> bool:
    """Whether the configured upstream proxy already knows how to route this key."""
    return _key_matches(api_key, PROXY_KEY_PREFIXES)


def is_akash_key(api_key: str | None) -> bool:
    """Whether the key uses AkashML's direct OpenAI-compatible route."""
    return _key_matches(api_key, AKASH_KEY_PREFIXES)


def resolve_upstream() -> str:
    """Return the provider proxy used for provider keys it supports."""
    return os.environ.get(UPSTREAM_ENV, "").strip().rstrip("/") or DEFAULT_UPSTREAM


def resolve_timeout() -> float:
    """Return a transport timeout without imposing any inference-token policy."""
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if raw:
        try:
            timeout = float(raw)
        except ValueError:
            return float(DEFAULT_TIMEOUT_SECONDS)
        if timeout > 0:
            return timeout
    return float(DEFAULT_TIMEOUT_SECONDS)


def _configured_direct_route() -> DirectProviderRoute:
    upstream = os.environ.get(DIRECT_UPSTREAM_ENV, "").strip()
    if not upstream:
        raise GatewayConfigurationError(f"direct provider routing requires {DIRECT_UPSTREAM_ENV}")
    return DirectProviderRoute(
        upstream=upstream,
        auth_header=os.environ.get(DIRECT_AUTH_HEADER_ENV, "").strip()
        or DEFAULT_DIRECT_AUTH_HEADER,
        auth_value_template=os.environ.get(DIRECT_AUTH_VALUE_TEMPLATE_ENV, "").strip()
        or DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE,
    )


def resolve_direct_provider(api_key: str | None) -> DirectProviderRoute | None:
    """Resolve a direct route for provider keys that bypass the upstream proxy.

    OpenRouter/Chutes-style keys stay on ``KATA_INFERENCE_GATEWAY_UPSTREAM``.
    AkashML has a built-in direct route. Operators can add one other direct route
    with a key-prefix allowlist, or set ``...DIRECT_ALLOW_UNKNOWN=1`` when their
    configured direct endpoint is intentionally the route for all other keys.
    """
    if not api_key or is_proxy_provider_key(api_key):
        return None

    prefixes = _split_csv(os.environ.get(DIRECT_KEY_PREFIXES_ENV))
    if prefixes and _key_matches(api_key, prefixes):
        return _configured_direct_route()
    if _env_truthy(DIRECT_ALLOW_UNKNOWN_ENV):
        return _configured_direct_route()
    if is_akash_key(api_key):
        return DirectProviderRoute(
            upstream=os.environ.get(AKASH_UPSTREAM_ENV, "").strip() or DEFAULT_AKASH_UPSTREAM
        )
    return None


class MinerInferenceGatewayHandler(BaseHTTPRequestHandler):
    """Forward only valid inference requests from the sealed agent network."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if urlsplit(self.path).path == HEALTH_PATH:
            self._send_json(200, {"status": "ok", "service": "miner-inference-gateway"})
            return
        self._send_json(404, {"status": "error", "detail": "Only gateway health is available."})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == INFERENCE_PATH:
            upstream_path = INFERENCE_PATH + (f"?{parsed.query}" if parsed.query else "")
        elif _JOB_INFERENCE_PATH.fullmatch(parsed.path):
            # The job segment is a sealed-room correlation id, never an upstream route.
            upstream_path = INFERENCE_PATH + (f"?{parsed.query}" if parsed.query else "")
        else:
            self._read_body()
            self._send_json(
                404,
                {"status": "error", "detail": "Only POST /inference is allowed."},
            )
            return
        self._forward(upstream_path)

    def _forward(self, upstream_path: str) -> None:
        body = self._read_body()
        api_key = self.headers.get("x-inference-api-key", "").strip()
        if not api_key:
            # Never let an absent miner credential trigger a provider's default
            # account or fallback key. An inference-free baseline simply makes no
            # gateway calls; an agent that calls inference must fund it itself.
            self._send_json(
                401,
                {"status": "error", "detail": "A miner inference API key is required."},
            )
            return
        request_headers = self._safe_request_headers()
        try:
            request = self._build_upstream_request(
                api_key=api_key,
                body=body,
                upstream_path=upstream_path,
                request_headers=request_headers,
            )
        except GatewayConfigurationError as error:
            self._send_json(502, {"status": "error", "detail": str(error)})
            return
        try:
            with urlopen(request, timeout=resolve_timeout()) as response:
                self._relay_response(response.status, response.headers.items(), response.read())
        except HTTPError as error:
            self._relay_response(error.code, error.headers.items(), error.read())
        except URLError as error:
            self._send_json(
                502,
                {"status": "error", "detail": f"gateway could not reach provider: {error.reason}"},
            )

    def _safe_request_headers(self) -> dict[str, str]:
        return {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _SKIP_REQUEST_HEADERS
        }

    def _build_upstream_request(
        self,
        *,
        api_key: str,
        body: bytes,
        upstream_path: str,
        request_headers: dict[str, str],
    ) -> Request:
        direct_provider = resolve_direct_provider(api_key)
        if direct_provider is not None:
            headers = {
                key: value
                for key, value in request_headers.items()
                if key.lower() not in {"x-inference-api-key", direct_provider.auth_header.lower()}
            }
            headers.setdefault("Content-Type", "application/json")
            headers[direct_provider.auth_header] = self._render_auth_value(
                direct_provider.auth_value_template,
                api_key,
            )
            return Request(
                direct_provider.upstream,
                data=body if body else None,
                headers=headers,
                method="POST",
            )

        headers = dict(request_headers)
        headers["x-inference-api-key"] = api_key
        return Request(
            resolve_upstream() + upstream_path,
            data=body if body else None,
            headers=headers,
            method="POST",
        )

    @staticmethod
    def _render_auth_value(template: str, api_key: str) -> str:
        if "{api_key}" not in template:
            raise GatewayConfigurationError(
                f"{DIRECT_AUTH_VALUE_TEMPLATE_ENV} must include {{api_key}}"
            )
        try:
            return template.format(api_key=api_key)
        except (IndexError, KeyError, ValueError) as error:
            raise GatewayConfigurationError(
                f"{DIRECT_AUTH_VALUE_TEMPLATE_ENV} must use {{api_key}}"
            ) from error

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def _relay_response(self, status: int, header_items, body: bytes) -> None:
        self.send_response(status)
        for key, value in header_items:
            if key.lower() not in _SKIP_RESPONSE_HEADERS:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        # Requests may include source code and miner credentials; never log them.
        return


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MinerInferenceGatewayHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("KATA_INFERENCE_GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("KATA_INFERENCE_GATEWAY_PORT", "8000"))
    server = build_server(host, port)
    print(
        f"SN60 miner-funded inference gateway listening on {host}:{port} -> {resolve_upstream()}",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
