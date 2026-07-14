"""The SN60 bitsec subnet plugin.

Importing this package registers the SN60 plugin with the core registry. It is the
reference plugin -- the first tenant of the multi-subnet platform.
"""

from __future__ import annotations

from kata.packages.registry import register_plugin

from .plugin import Sn60BitsecPlugin, Sn60Problems, Sn60RawRun
from .round import build_sn60_round_result, run_sn60_plugin_round

#: The singleton SN60 plugin instance the core resolves by evaluator id.
SN60_BITSEC_PLUGIN = Sn60BitsecPlugin()

register_plugin(SN60_BITSEC_PLUGIN)

__all__ = [
    "SN60_BITSEC_PLUGIN",
    "Sn60BitsecPlugin",
    "Sn60Problems",
    "Sn60RawRun",
    "build_sn60_round_result",
    "run_sn60_plugin_round",
]
