#!/usr/bin/env python3
"""F24 (Strategy S348 §2, D-3296) — the project's OWN test script is run, and "0 tests ran" is never a pass.

DESTINATION: Hepherus-Forge/checks/scripts/read_tests.py. Two commands, standard library only:
  plan   prints the shell command that runs the declared "test" script ("" = nothing to run): vitest and jest are asked for
         their JSON result as well; any other script runs as it is.
  read   writes tests.json: counts and test NAMES only, never output.
tests.json status: "no_tests" (no test files in the repository yet: said in plain words, not a pass of tests), "ok" (a
readable result with at least one test), "unreadable" (test files exist and no script, no readable result, or 0 tests ran:
a FAILURE). A non-zero exit with no failing test named still counts as one failure.

The project's code runs in a container that shares nothing with the check; its result is read as untrusted text.
NOT covered: end-to-end specs (folders e2e, playwright, cypress, or a file that imports their runner) are not unit tests and
are not counted as test files here; a script that prints a false summary (the customer's own code in the customer's runner).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

_TEST_FILE = re.compile(r"(?:^|/)(?:__tests__/[^/]+|[^/]+\.(?:test|spec))\.[cm]?[jt]sx?$", re.I)
_NOT_UNIT = re.compile(r"(?:^|/)(?:e2e|playwright|cypress|node_modules|\.hepherus-checks)(?:/|$)", re.I)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


_E2E_TEXT = re.compile(r"""^\s*(?:import\b[^\n]*|(?:const|let|var)\b[^\n]*require\()\s*['"]@playwright/test['"]""", re.M)
_IS_TEST_TEXT = re.compile(r"\b(?:it|test|describe|suite)\s*(?:\.\w+\s*)?\(")


def test_files(tracked: List[str], read: Callable[[str], Optional[str]]) -> List[str]:
    """The repository's unit-test files: the name says so and the text holds a test, not an end-to-end one. A file that
    cannot be read counts (fail closed). Input: tracked paths, a reader. Returns: the matching ones."""
    out = []
    for p in tracked:
        if _TEST_FILE.search(p) and not _NOT_UNIT.search(p):
            text = read(p)
            if text is None or (_IS_TEST_TEXT.search(text) and not _E2E_TEXT.search(text)):
                out.append(p)
    return out


def script_of(package_json: Optional[str]) -> str:
    """package.json's declared test script. Input: its text. Returns: the script ("" = none or unreadable)."""
    try:
        s = (json.loads(package_json or "").get("scripts") or {}).get("test")
        return s if isinstance(s, str) else ""
    except (ValueError, AttributeError, RecursionError):
        return ""


def command(script: str, files: List[str]) -> str:
    """How to run the declared script. Input: the script, the test files. Returns: a shell command ("" = nothing to run)."""
    if not files or not script.strip():
        return ""
    if re.search(r"&&|\|\||[;|]", script):          # npm would hand the extra arguments to the LAST command
        return "npm test"
    if re.search(r"\bvitest\b", script):
        return "npm test -- --reporter=json --outputFile=jest.json"
    if re.search(r"\bjest\b", script):
        return "npm test -- --json --outputFile=jest.json"
    return "npm test"


def _from_json(text: Optional[str]) -> Optional[Tuple[int, int, int, List[str]]]:
    """(run, passed, failed, failing names) from vitest's or jest's JSON. Input: the text. Returns: the counts or None."""
    try:
        d = json.loads(text or "")
        results = d.get("testResults") or []
        failing = [str(t.get("fullName") or "") for r in results for t in r.get("assertionResults", []) if t.get("status") == "failed"]
        broken = [r for r in results if r.get("status") == "failed"
                  and not any(t.get("status") == "failed" for t in r.get("assertionResults", []))]   # a file that could not load
        return int(d["numTotalTests"]), int(d["numPassedTests"]), int(d["numFailedTests"]) + len(broken), failing
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return None


def _from_log(text: Optional[str]) -> Optional[Tuple[int, int, int, List[str]]]:
    """The same counts from a runner's printed summary (vitest, jest, node's own runner). Input: the log. Returns: counts or None."""
    t = _ANSI.sub("", text or "")
    m = re.findall(r"^\s*(?:#|ℹ)\s+(tests|pass|fail)\s+(\d+)\s*$", t, re.M)
    if m:
        d = {k: int(v) for k, v in m}
        if "tests" in d:
            return d["tests"], d.get("pass", 0), d.get("fail", 0), []
    lines = re.findall(r"^\s*Tests:?\s+(.*\d.*)$", t, re.M)
    if lines:
        n = {k: int(v) for v, k in re.findall(r"(\d+)\s+(passed|failed)", lines[-1])}
        if n:
            return n.get("passed", 0) + n.get("failed", 0), n.get("passed", 0), n.get("failed", 0), []
    return None


def read_result(package_json: Optional[str], files: List[str], result_json: Optional[str], log: Optional[str],
                exit_code: int) -> Dict[str, Any]:
    """The tests block. Input: package.json text, the unit-test files, the JSON result, the log, the script's exit code
    (-1 = it did not run). Returns: {run, passed, failed, failing, status, note}."""
    out: Dict[str, Any] = {"run": 0, "passed": 0, "failed": 0, "failing": [], "status": "unreadable", "note": ""}
    if not files:
        return {**out, "status": "no_tests", "note": "no tests: the repository has no test files yet"}
    if not script_of(package_json):
        return {**out, "note": "there are test files but package.json has no test script"}
    got = _from_json(result_json) or _from_log(log)
    if got is None or exit_code < 0:
        return {**out, "note": "the test script's result could not be read"}
    run, passed, failed, failing = got
    if exit_code != 0 and not failed:
        failed = 1
    if passed + failed < 1:
        return {**out, "note": "there are test files but 0 tests ran"}
    return {"run": run, "passed": passed, "failed": failed, "failing": [f[:200] for f in failing[:200]], "status": "ok", "note": ""}


def _text(path: str) -> Optional[str]:
    """A file's text, or None when it is not there (or is a link: never followed). Input: the path. Returns: str or None."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            return fh.read(5_000_000)
    except OSError:
        return None


def _tracked() -> List[str]:
    """The repository's tracked paths. Returns: a list."""
    return [p for p in subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.decode(
        "utf-8", "replace").split("\0") if p]


def main() -> None:
    """plan: print the command. read: write tests.json. Returns: None."""
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("plan", "read"))
    ap.add_argument("--result", default="jest.json")
    ap.add_argument("--log", default="test.log")
    ap.add_argument("--exit", type=int, default=-1)
    ap.add_argument("--out", default="tests.json")
    a = ap.parse_args()
    pkg, files = _text("package.json"), test_files(_tracked(), _text)
    if a.what == "plan":
        print(command(script_of(pkg), files))
        return
    block = read_result(pkg, files, _text(a.result), _text(a.log), a.exit)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(block, fh)
    print("tests:", block["note"] or f"{block['run']} run, {block['failed']} failed")


if __name__ == "__main__":
    main()
