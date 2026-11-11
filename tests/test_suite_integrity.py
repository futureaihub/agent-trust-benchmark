"""Guards on the test suite itself.

The red-team modules used to be report generators: 45 functions named ``test_*``
that printed PASS/FAIL and asserted nothing, so they stayed green no matter what
the evaluator did. They also called themselves at import time, which meant every
case ran twice per session -- once for the report and once for pytest.

Assertions cannot be added by convention, because the failure mode is silent.
These tests fail loudly instead.
"""

import ast
from pathlib import Path

TESTS_DIR = Path(__file__).parent

# pytest.raises()/fail()/skip() are assertions in every way that matters.
ASSERTION_LIKE_CALLS = {"raises", "fail", "skip"}


def _test_modules():
    return sorted(p for p in TESTS_DIR.glob("test_*.py"))


def _test_functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            yield node


def _has_assertion(node):
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        if isinstance(child, ast.Call) and getattr(child.func, "attr", "") in ASSERTION_LIKE_CALLS:
            return True
    return False


def test_every_test_function_asserts_something():
    """A test that cannot fail is a comment with extra steps."""
    silent = []
    for path in _test_modules():
        tree = ast.parse(path.read_text())
        for node in _test_functions(tree):
            if not _has_assertion(node):
                silent.append(f"{path.name}::{node.name}")

    assert silent == [], f"test functions that assert nothing: {silent}"


def test_no_test_function_is_called_at_import_time():
    """A test *called* at module scope runs once at collection and once as a test."""
    offenders = []
    for path in _test_modules():
        tree = ast.parse(path.read_text())
        for node in tree.body:  # module level only
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                continue
            func = node.value.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name.startswith("test"):
                offenders.append(f"{path.name}:{node.lineno}: {name}()")

    assert offenders == [], f"test functions invoked at import time: {offenders}"


def test_the_guard_catches_a_silent_test(tmp_path):
    """Negative control: the check above must report a print-only test."""
    sample = tmp_path / "test_sample.py"
    sample.write_text(
        "def test_silent():\n"
        "    print('PASS')\n"
        "\n"
        "def test_asserting():\n"
        "    assert True\n"
        "\n"
        "test_silent()\n"
    )

    tree = ast.parse(sample.read_text())

    assert [n.name for n in _test_functions(tree) if not _has_assertion(n)] == ["test_silent"]
    assert any(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and getattr(node.value.func, "id", "") == "test_silent"
        for node in tree.body
    )
