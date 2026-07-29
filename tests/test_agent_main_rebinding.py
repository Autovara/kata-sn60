"""SN60's screening must reject a rebound entrypoint too.

SN60 keeps its own `static_screen` because it adds subnet-specific rules on top of the generic
contract -- notably `sn60.direct_constant_report`, which detects a hardcoded answer bank. That rule
inspects the SELECTED agent_main, so entrypoint rebinding bypassed the one check most directly
aimed at the incident class it exists for.

The analysis now lives in `kata.ast_utils` and both layers call it, so the two cannot drift into
different ideas of what "the entrypoint" is.
"""

from __future__ import annotations

import pathlib

import pytest

from kata_sn60.static_screening import SEALED_KEY_FILENAME, screen_sn60_static_bundle

#: Plausible ciphertext, so the sealed-key rule does not mask the finding under test.
SEALED = "04" + "ab" * 120

DECOY = '''
def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": _real(project_dir)}

def _real(directory):
    return [{"file": str(directory), "severity": "high", "description": "computed"}]

def _canned(project_dir=None, inference_api=None):
    return {"vulnerabilities": [{"file": "Vault.sol", "severity": "critical", "description": "x"}]}
'''


def _screen(agent_source: str) -> list[str]:
    bundle = {"agent.py": agent_source, SEALED_KEY_FILENAME: SEALED}
    return [f.rule_id for f in screen_sn60_static_bundle(bundle)]


ROUTES = {
    "assignment": "agent_main = _canned",
    "def nested in control flow": (
        "if True:\n    def agent_main(p=None, i=None):\n        return {}"
    ),
    "import alias": "from helpers.canned import report as agent_main",
    "for-loop target": "for agent_main in (_canned,):\n    pass",
    "global rebind": "def _i():\n    global agent_main\n    agent_main = _canned\n_i()",
    "globals subscript": "globals()['agent_main'] = _canned",
    "setattr on this module": "import sys\nsetattr(sys.modules[__name__], 'agent_main', _canned)",
    "exec": "exec('agent_main = _canned')",
}


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_sn60_rejects_a_rebound_entrypoint(route):
    findings = _screen(DECOY + "\n" + ROUTES[route] + "\n")
    assert findings, f"{route} still passes SN60 screening"
    assert findings[0].startswith("sn60.agent_main_"), findings


def test_sn60_rejects_a_star_import():
    assert _screen(DECOY + "\nfrom helpers.canned import *\n") == ["sn60.agent_main_star_import"]


def test_sn60_rejects_a_decorated_entrypoint():
    source = '''
def _swap(fn):
    return fn

@_swap
def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": [{"file": "A.sol", "severity": "high", "description": "c"}]}
'''
    assert _screen(source) == ["sn60.agent_main_decorated"]


def test_the_canned_report_rule_is_what_rebinding_was_bypassing():
    """The point of the whole fix, stated as a test.

    A hardcoded report IS detected when it sits in the inspected function. Rebinding moved it
    somewhere the rule never looked, so the check reported clean on exactly the submission it
    exists to catch.
    """
    direct = '''
def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": [{"file": "Vault.sol", "severity": "critical", "description": "x"}]}
'''
    assert "sn60.direct_constant_report" in _screen(direct)
    # The same payload, reached by rebinding, must no longer slip past.
    assert _screen(DECOY + "\nagent_main = _canned\n") == ["sn60.agent_main_rebound"]


REVIEW_ROUTES = {
    "TYPE_CHECKING rebound True": (
        "TYPE_CHECKING = True\nif TYPE_CHECKING:\n    agent_main = _canned"
    ),
    "TYPE_CHECKING else": (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n    pass\nelse:\n    agent_main = _canned"
    ),
    "except* body": "try:\n    pass\nexcept* Exception:\n    agent_main = _canned",
    "locals() write": "locals()['agent_main'] = _canned",
    "globals().__setitem__": "globals().__setitem__('agent_main', _canned)",
    "module attribute": "import sys\nsys.modules[__name__].agent_main = _canned",
    "module __dict__": "import sys\nsys.modules[__name__].__dict__['agent_main'] = _canned",
}


@pytest.mark.parametrize("route", sorted(REVIEW_ROUTES))
def test_sn60_rejects_routes_found_in_review(route):
    """These passed the first version of the rule. SN60 shares the analysis, so it inherits both
    the fix and this coverage."""
    findings = _screen(DECOY + "\n" + REVIEW_ROUTES[route] + "\n")
    assert findings, f"{route} still passes SN60 screening"
    assert findings[0].startswith("sn60.agent_main_"), findings


REVIEW_LEGITIMATE = {
    "eval of an expression": "_v = eval('1 + 1')",
    "__import__": "_m = __import__('math')",
    "vars(obj) write": "class _C:\n    pass\n_c = _C()\nvars(_c)['agent_main'] = 1",
    "walrus in a lambda": "_f = lambda x: (agent_main := x)",
}


@pytest.mark.parametrize("case", sorted(REVIEW_LEGITIMATE))
def test_sn60_accepts_code_that_cannot_reach_the_entrypoint(case):
    source = DECOY + "\n" + REVIEW_LEGITIMATE[case] + "\n"
    assert _screen(source) == [], f"{case} was rejected"


def test_an_honest_computed_agent_is_accepted():
    source = '''
def _analyze(directory):
    return [{"file": str(directory), "severity": "high", "description": "computed"}]

def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": _analyze(project_dir)}
'''
    assert _screen(source) == []


def test_the_reigning_king_still_passes():
    """A screening rule that rejected the incumbent would take the lane down on its next round."""
    king = pathlib.Path(__file__).resolve().parents[2] / "kata" / "kings" / "sn60__bitsec" / "miner"
    agent = king / "agent.py"
    if not agent.is_file():
        pytest.skip("the competition repository is not checked out beside this one")
    bundle = {"agent.py": agent.read_text(encoding="utf-8")}
    sealed = king / SEALED_KEY_FILENAME
    if sealed.is_file():
        bundle[SEALED_KEY_FILENAME] = sealed.read_text(encoding="utf-8").strip()
    assert [f.rule_id for f in screen_sn60_static_bundle(bundle)] == []


ANNOTATED_ROUTES = {
    "annotated globals subscript": 'globals()["agent_main"]: object = _canned',
    "annotated module attribute": (
        "import sys\nsys.modules[__name__].agent_main: object = _canned"
    ),
    "annotated module __dict__": (
        'import sys\nsys.modules[__name__].__dict__["agent_main"]: object = _canned'
    ),
}


@pytest.mark.parametrize("route", sorted(ANNOTATED_ROUTES))
def test_sn60_rejects_an_annotated_namespace_write(route):
    """Matched ``ast.Assign`` only, so the same write with an annotation on it passed. SN60 shares
    the analysis and inherits both the fix and this coverage."""
    findings = _screen(DECOY + "\n" + ANNOTATED_ROUTES[route] + "\n")
    assert findings, f"{route} still passes SN60 screening"
    assert findings[0] == "sn60.agent_main_rebound", findings


@pytest.mark.parametrize("call", ["locals", "vars"])
def test_sn60_accepts_a_function_scoped_namespace_write(call):
    """Inside a function these are that function's locals and cannot reach the module global."""
    source = DECOY + f'\ndef helper():\n    {call}()["agent_main"] = _canned\nhelper()\n'
    assert _screen(source) == [], f"{call}() inside a function was rejected"


def test_sn60_rejects_a_deleted_entrypoint():
    source = DECOY + "\ndel agent_main\ndef __getattr__(name):\n    return _canned\n"
    assert _screen(source) == ["sn60.agent_main_deleted"]


DEFINITION_TIME_ROUTES = {
    "function default": (
        "def helper(value=locals().__setitem__('agent_main', _canned)):\n    pass"
    ),
    "eager return annotation": (
        "def helper() -> locals().__setitem__('agent_main', _canned):\n    pass"
    ),
    "helper decorator": (
        "def identity(fn):\n"
        "    return fn\n"
        "@(locals().__setitem__('agent_main', _canned), identity)[1]\n"
        "def helper():\n"
        "    pass"
    ),
    "lambda default": (
        "helper = lambda value=locals().__setitem__('agent_main', _canned): value"
    ),
}


@pytest.mark.parametrize("route", sorted(DEFINITION_TIME_ROUTES))
def test_sn60_rejects_a_definition_time_namespace_write(route):
    findings = _screen(DECOY + "\n" + DEFINITION_TIME_ROUTES[route] + "\n")
    assert findings == ["sn60.agent_main_rebound"], f"{route}: {findings}"


def test_sn60_rejects_a_walrus_in_a_lambda_default():
    source = DECOY + "\nhelper = lambda value=(agent_main := _canned): value\n"
    assert _screen(source) == ["sn60.agent_main_rebound"]


def test_sn60_accepts_a_walrus_confined_to_a_function_body():
    source = (
        DECOY
        + "\ndef helper():\n"
        "    value = (agent_main := _canned)\n"
        "    return value\n"
    )
    assert _screen(source) == []


MODULE_ALIAS_ROUTES = {
    "module object": (
        "import sys\nmodule = sys.modules[__name__]\nmodule.agent_main = _canned"
    ),
    "module mapping": "namespace = globals()\nnamespace['agent_main'] = _canned",
    "function-local module object": (
        "def install():\n"
        "    import sys\n"
        "    module = sys.modules[__name__]\n"
        "    module.agent_main = _canned\n"
        "install()"
    ),
    "module registry": (
        "import sys\n"
        "registry = sys.modules\n"
        "module = registry[__name__]\n"
        "module.agent_main = _canned"
    ),
}


@pytest.mark.parametrize("route", sorted(MODULE_ALIAS_ROUTES))
def test_sn60_rejects_a_write_through_a_module_alias(route):
    findings = _screen(DECOY + "\n" + MODULE_ALIAS_ROUTES[route] + "\n")
    assert findings == ["sn60.agent_main_rebound"], f"{route}: {findings}"


FOURTH_REVIEW_ROUTES = {
    "module type setattr": (
        "import sys\n"
        "type(sys).__setattr__(sys.modules[__name__], 'agent_main', _canned)"
    ),
    "mapping alias augmented union": (
        "namespace = globals()\nnamespace |= {'agent_main': _canned}"
    ),
    "module registry get": (
        "import sys\nsys.modules.get(__name__).agent_main = _canned"
    ),
    "module spec name": (
        "import sys\nsys.modules[__spec__.name].agent_main = _canned"
    ),
}


@pytest.mark.parametrize("route", sorted(FOURTH_REVIEW_ROUTES))
def test_sn60_rejects_routes_found_in_the_fourth_review(route):
    findings = _screen(DECOY + "\n" + FOURTH_REVIEW_ROUTES[route] + "\n")
    assert findings == ["sn60.agent_main_rebound"], f"{route}: {findings}"
