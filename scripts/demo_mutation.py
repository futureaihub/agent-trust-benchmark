#!/usr/bin/env python3
"""Demonstrate that the test suite can fail.

The claim this project makes about itself is not "281 tests pass". It is
"the suite detects a broken invariant, and I can show you the number". This
script runs that experiment end to end:

  1. run the suite unmodified          -> expect all green
  2. neuter CHECK 8 in the evaluator   -> expect failures
  3. restore the file byte-for-byte    -> expect the same hash it started with

The exit code is inverted on purpose. This script succeeds only if the
mutation was caught; if the suite stays green with a broken outcome check,
it exits non-zero, because then the suite is lying about what it protects.

Usage:
    python scripts/demo_mutation.py            # full demo, ~30s
    python scripts/demo_mutation.py --verbose  # also stream pytest output

Requires the OPA binary (./scripts/setup.sh) because 44 of the tests shell
out to it.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "app" / "evaluator.py"

# The CHECK 8 comparison appears twice in evaluator.py: once on the refusal
# path and once on the completing path. Anchor on the check name that follows
# the second one so the mutation cannot land on the wrong branch, and so a
# shifted line number does not silently disable the demo.
ORIGINAL = (
    "        outcome_ok = actual_sorted == expected_sorted\n"
    "        checks.append(\n"
    "            {\n"
    '                "name": "business_outcome_matches_expected",\n'
)
MUTATED = (
    "        outcome_ok = True  # MUTATION: CHECK 8 no longer compares anything\n"
    "        checks.append(\n"
    "            {\n"
    '                "name": "business_outcome_matches_expected",\n'
)

SUMMARY_RE = re.compile(r"(\d+) (passed|failed)")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def run_pytest(verbose: bool) -> tuple[int, int, int]:
    """Return (returncode, passed, failed) for one pytest run."""
    cmd = [sys.executable, "-m", "pytest", "-q", "--tb=no", "-p", "no:cacheprovider"]
    proc = subprocess.run(
        cmd,
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    output = proc.stdout + proc.stderr
    if verbose:
        print(output.rstrip())
    passed = failed = 0
    for count, kind in SUMMARY_RE.findall(output):
        if kind == "passed":
            passed = int(count)
        else:
            failed = int(count)
    return proc.returncode, passed, failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="stream pytest output")
    args = parser.parse_args()

    if not TARGET.exists():
        print(f"error: {TARGET} not found; run from a checkout of the repository")
        return 2

    original_source = TARGET.read_text()
    original_hash = digest(original_source)

    occurrences = original_source.count(ORIGINAL)
    if occurrences != 1:
        print(
            f"error: expected exactly 1 CHECK 8 anchor in {TARGET.name}, found {occurrences}.\n"
            "       The evaluator has changed; update ORIGINAL in this script rather than\n"
            "       guessing, otherwise the demo would mutate code nobody is testing."
        )
        return 2

    print("baseline: running the suite unmodified")
    rc, passed, failed = run_pytest(args.verbose)
    if rc != 0 or failed:
        print(
            f"  FAILED: baseline is not green ({passed} passed, {failed} failed).\n"
            "  A mutation demo proves nothing if the suite was already failing."
        )
        return 1
    baseline_passed = passed
    print(f"  {passed} passed, {failed} failed")

    print("mutation: CHECK 8 now returns True without comparing anything")
    m_passed = m_failed = 0
    completed = False
    try:
        TARGET.write_text(original_source.replace(ORIGINAL, MUTATED))
        _, m_passed, m_failed = run_pytest(args.verbose)
        completed = True
    finally:
        # Restore unconditionally: a crashed run must not leave mutated source
        # on disk for the next person to mistake for the real evaluator.
        TARGET.write_text(original_source)

    restored_hash = digest(TARGET.read_text())
    if restored_hash != original_hash:
        print(
            f"  FATAL: restore failed for {TARGET}.\n"
            f"  expected sha256 {original_hash}\n"
            f"  actual   sha256 {restored_hash}\n"
            "  Run `git checkout -- app/evaluator.py` before doing anything else."
        )
        return 3

    if not completed:
        print("  ERROR: the mutated test run did not complete; see output above.")
        return 4

    if m_failed == 0:
        print(
            f"  NOT CAUGHT: {m_passed} passed with a broken outcome check.\n"
            "  The suite does not protect CHECK 8 and its green status is not evidence."
        )
        return 1

    print(f"  {m_passed} passed, {m_failed} failed")

    print()
    print(f"  baseline            {baseline_passed:>4} passed, {0:>4} failed")
    print(f"  CHECK 8 neutered    {m_passed:>4} passed, {m_failed:>4} failed")
    print(f"  evaluator restored  sha256 {original_hash[:16]}... (byte-identical)")
    print()
    print(f"  {m_failed} test(s) detect the broken invariant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
