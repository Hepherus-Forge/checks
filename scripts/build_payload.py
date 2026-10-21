#!/usr/bin/env python3
"""T798 — the deterministic check + payload builder for the Hepherus connector-checks reusable workflow.

DESTINATION: Hepherus-Forge/checks/scripts/build_payload.py (published + pinned with the reusable workflow).
It runs IN THE CUSTOMER'S OWN GitHub Actions runner (never on Hepherus's systems) and writes payload.json:
COUNTS + PATHS per §8 check, the §6.1 style-guide STRUCTURE when the declared styling file changed, and a
pass/fail conclusion. It NEVER emits code bodies or .env VALUES — settings "mismatch" is reported as NAMES
only, secrets as PATHS only. Pure functions so the logic is reviewable and unit-testable off a runner.

Per-stack hard-coded-styling patterns here are the JS/TS/React/Next set (T797 §3d). A real caller pins the
patterns + the test runner for its stack.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from typing import Dict, List, Optional, Set, Tuple

# §8 hard-coded styling patterns (JS/TS/React/Next; T797 §3d).
_STYLE_PATTERNS = [
    re.compile(r"#[0-9a-fA-F]{3,8}\b"),                                   # hex colour literal
    re.compile(r"\b(?:rgb|rgba|hsl|hsla)\("),                            # colour function literal
    re.compile(r"\b(?:text|bg|border|w|h|p|m|gap)-\[[^\]]+\]"),          # tailwind arbitrary value
    re.compile(r"style=\{\{[^}]*(?:color|font|fontSize)"),               # inline style
    re.compile(r":\s*\d+(?:\.\d+)?(?:px|rem)\b"),                        # px/rem literal
]
# §8 secret HINTS (presence only — the value is never emitted; the server re-scans too).
_SECRET_HINTS = [
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
_CODE_EXT = (".tsx", ".ts", ".jsx", ".js", ".css", ".scss")


def _read(path: str) -> str:
    try:
        return open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return ""


def hardcoded_styling(changed: List[str], styling_path: str) -> Tuple[int, List[str]]:
    """Paths among the CHANGED code files (excluding the declared styling source) that carry a hard-coded
    styling literal. Returns (count, paths). Counts + paths only — never the matched text."""
    paths = []
    for p in changed:
        if not p.endswith(_CODE_EXT) or p == styling_path or not os.path.exists(p):
            continue
        body = _read(p)
        if any(pat.search(body) for pat in _STYLE_PATTERNS):
            paths.append(p)
    return len(paths), paths


def secrets_in_changed_files(changed: List[str]) -> Tuple[int, List[str]]:
    """Changed files whose body matches a secret hint. Returns (count, PATHS) — never the value."""
    paths = []
    for p in changed:
        if not os.path.exists(p):
            continue
        body = _read(p)
        if any(h.search(body) for h in _SECRET_HINTS):
            paths.append(p)
    return len(paths), paths


def settings_mismatch(changed: List[str], settings_template: str) -> Tuple[int, List[str]]:
    """NAMES the changed code reads (process.env.X / os.getenv('X')) that are ABSENT from the settings
    template. Returns (count, NAMES). Reads the template's NAME before '=' only — never a value (the
    RAILWAY_URL vs BACKEND_URL class, D-195)."""
    code_names: Set[str] = set()
    for p in changed:
        if not p.endswith(_CODE_EXT) or not os.path.exists(p):
            continue
        body = _read(p)
        code_names |= set(re.findall(r"process\.env\.([A-Z0-9_]+)", body))
        code_names |= set(re.findall(r"os\.getenv\(['\"]([A-Z0-9_]+)['\"]", body))
    template_names: Set[str] = set()
    if os.path.exists(settings_template):
        for line in open(settings_template, encoding="utf-8", errors="ignore"):
            m = re.match(r"\s*([A-Z0-9_]+)\s*=", line)
            if m:
                template_names.add(m.group(1))
    missing = sorted(code_names - template_names)
    return len(missing), missing


def style_guide(changed: List[str], styling_path: str) -> Optional[Dict[str, object]]:
    """§6.1 structure, ONLY when the declared styling file changed and ONLY from that path (the allowlist is
    this one path). Each value: name·category·value(≤64 chars)·placeholder flag. Returns the structure or
    None. Reads NO other path — 'another path' cannot ride along (T797 §14 case 8)."""
    if styling_path not in changed or not os.path.exists(styling_path):
        return None
    try:
        tokens = json.loads(_read(styling_path))
    except Exception:
        tokens = {}
    values: List[Dict[str, object]] = []

    def walk(category: str, obj) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, dict):
                    walk(k, v)
                else:
                    values.append({"name": k, "category": category, "value": str(v)[:64],
                                   "placeholder": bool(re.search(r"(?i)placeholder", str(k) + str(v)))})

    walk("root", tokens)
    return {"source": styling_path, "values": values[:1000], "components": []}


def build_payload(changed: List[str], styling_path: str, settings_template: str, tests: Dict,
                  vuln: Dict, commit_sha: str, repository: str, repository_id: str) -> Dict[str, object]:
    """Assemble the full payload and compute the conclusion. Pure. Returns the payload dict."""
    hs_c, hs_p = hardcoded_styling(changed, styling_path)
    se_c, se_p = secrets_in_changed_files(changed)
    sm_c, sm_p = settings_mismatch(changed, settings_template)
    payload: Dict[str, object] = {
        "schema": "hepherus.checks/1",
        "commit_sha": commit_sha,
        "repository": repository,
        "repository_id": str(repository_id),
        "checks": {
            "hardcoded_styling": {"count": hs_c, "paths": hs_p[:500]},
            "secrets_in_changed_files": {"count": se_c, "paths": se_p[:500]},
            "settings_mismatch": {"count": sm_c, "paths": sm_p[:500]},   # NAMES, not values
            "vulnerable_packages": {k: int(vuln.get(k, 0)) for k in ("critical", "high", "moderate", "low")},
        },
        "tests": {"run": int(tests.get("run", 0)), "passed": int(tests.get("passed", 0)),
                  "failed": int(tests.get("failed", 0)), "failing": list(tests.get("failing", []))[:200]},
    }
    sg = style_guide(changed, styling_path)
    if sg is not None:
        payload["style_guide"] = sg
    c = payload["checks"]
    failed = bool(c["hardcoded_styling"]["count"] or c["secrets_in_changed_files"]["count"]
                  or c["settings_mismatch"]["count"] or payload["tests"]["failed"]
                  or c["vulnerable_packages"]["critical"] or c["vulnerable_packages"]["high"])
    payload["conclusion"] = "fail" if failed else "pass"
    return payload


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--changed", required=True, help="file listing changed paths, one per line")
    ap.add_argument("--styling-path", required=True)
    ap.add_argument("--settings-template", required=True)
    ap.add_argument("--tests", required=True, help="tests.json")
    ap.add_argument("--vuln", required=True, help="vuln.json")
    ap.add_argument("--commit-sha", required=True)
    ap.add_argument("--repository", required=True)
    ap.add_argument("--repository-id", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    changed = [l.strip() for l in open(a.changed, encoding="utf-8").read().splitlines() if l.strip()]
    tests = json.load(open(a.tests, encoding="utf-8"))
    vuln = json.load(open(a.vuln, encoding="utf-8"))
    payload = build_payload(changed, a.styling_path, a.settings_template, tests, vuln,
                            a.commit_sha, a.repository, a.repository_id)
    json.dump(payload, open(a.out, "w", encoding="utf-8"))


if __name__ == "__main__":
    main()
