from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

MANIFEST = (
    Path(__file__).resolve().parents[1] / "deploy" / "sn60-runner" / "docker-compose.yml"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _block_json(document: str, variable: str) -> dict[str, object]:
    lines = document.splitlines()
    marker = f"      {variable}: >-"
    try:
        start = lines.index(marker) + 1
    except ValueError:
        raise AssertionError(f"{variable} must be a literal measured JSON block") from None

    block: list[str] = []
    for line in lines[start:]:
        if line and not line.startswith("        "):
            break
        block.append(line[8:])

    value = json.loads("\n".join(block))
    assert isinstance(value, dict) and value
    return value


def test_phala_manifest_measures_public_security_policy() -> None:
    document = MANIFEST.read_text(encoding="utf-8")

    placeholders = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", document))
    assert placeholders == {"GHCR_TOKEN", "KATA_ROOM_AUTH_SECRET"}

    image = re.search(r"^\s+image:\s+(\S+)$", document, re.MULTILINE)
    assert image is not None
    assert "@sha256:" in image.group(1)
    assert _DIGEST.fullmatch(image.group(1).rsplit("@", 1)[1])

    project_images = _block_json(document, "KATA_SN60_TEE_IMAGE_DIGESTS_JSON")
    assert all(
        isinstance(project, str)
        and project
        and isinstance(digest, str)
        and _DIGEST.fullmatch(digest)
        for project, digest in project_images.items()
    )

    provider_routes = _block_json(document, "KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON")
    assert all(
        isinstance(provider, str)
        and provider
        and isinstance(route, dict)
        and set(route) == {"upstream"}
        and isinstance(route["upstream"], str)
        and urlsplit(route["upstream"]).scheme == "https"
        and bool(urlsplit(route["upstream"]).hostname)
        for provider, route in provider_routes.items()
    )
