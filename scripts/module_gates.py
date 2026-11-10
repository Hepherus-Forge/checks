#!/usr/bin/env python3
"""Mocca Build Guidelines v1.3 §6.4 — the three MODULAR gates ([[D-2743]], approved [[D-2747]]).

DESTINATION: Hepherus-Forge/checks/scripts/module_gates.py (published + pinned with the reusable workflow, beside
build_payload.py). Runs IN THE CUSTOMER'S OWN GitHub Actions runner. Pure functions + a thin git reader, so the
logic is unit-testable off a runner. Emits COUNTS + PATHS only — never code bodies.

  1. ONE-DOOR DUPLICATE COUNTER + RATCHET — for each shared job, the code files OUTSIDE the job's declared door
     file that carry that job's pattern. The allowed counts are the BASE commit's `.hepherus/duplicates.json`
     (read from the base, never from the PR — a PR cannot raise its own allowance). Any count above its base
     allowance FAILS (a second copy was added). Missing at base = 0 allowed.
  2. FILE-SIZE LIMIT — a code file over 800 lines FAILS, unless it already existed at the base at least that long
     and did not grow (existing large files may only shrink).
  3. NO CROSS-MODULE INTERNAL IMPORTS — a file in module A may import from module B only through one of B's door
     files (the declared doors whose module is B). A module with no door cannot be imported from another module.

The module map is `.hepherus/module_map.json` (written at setup from the approved plan; changed only through the
approved map-change path, v1.3 §2.12). Its sha256 and whether the PR changed it are reported so the Hepherus
server can verify it against the approved record.

HONEST LIMITS: detection is pattern-based and labelled so. Only the DEFAULT stack (§2.10: JavaScript/TypeScript —
Next.js / React / Node with Supabase, Resend) is supported; any other stack reports status "not_supported" with
the reason — never a false pass. "errors & empty states" has no reliable pattern: it is reported "not
pattern-checked" (the Reviewer judges it).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

SIZE_LIMIT = 800
MAP_PATH = ".hepherus/module_map.json"
DUP_PATH = ".hepherus/duplicates.json"
CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_SKIP_DIRS = ("node_modules/", ".next/", "dist/", "build/", ".hepherus/", ".hepherus-checks/", "coverage/")

# Per shared job: the patterns that mean "this file implements the job" (JS/TS default stack).
JOB_PATTERNS: Dict[str, List[re.Pattern]] = {
    "data_access": [re.compile(r"\bcreate(?:Browser|Server)?Client\s*\("), re.compile(r"\bnew\s+PrismaClient\s*\("),
                    re.compile(r"\bnew\s+(?:Pool|Client)\s*\(\s*\{[^}]*connectionString")],
    "messages": [re.compile(r"\bnew\s+Resend\s*\("), re.compile(r"\.emails\.send\s*\("),
                 re.compile(r"\bcreateTransport\s*\("), re.compile(r"api\.resend\.com")],
    "styling": [re.compile(r"#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b"), re.compile(r"\b(?:rgb|rgba|hsl|hsla)\("),
                re.compile(r"\b(?:text|bg|border|w|h|p|m|gap)-\[[^\]]+\]")],
    "formatting": [re.compile(r"\bnew\s+Intl\.(?:NumberFormat|DateTimeFormat)\s*\("),
                   re.compile(r"\.toLocale(?:Date|Time)?String\s*\("), re.compile(r"\.toFixed\s*\(")],
    "auth": [re.compile(r"\.auth\.get(?:User|Session)\s*\("), re.compile(r"\bgetServerSession\s*\(")],
    "config": [re.compile(r"\bprocess\.env\.[A-Z_]"), re.compile(r"\bimport\.meta\.env\.")],
    "logging": [re.compile(r"\bconsole\.(?:log|info|warn|error|debug)\s*\(")],
}
NOT_PATTERN_CHECKED = ("errors",)
_IMPORT_RE = re.compile(r"""(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+)['"]([^'"]+)['"]""", re.M)


def detect_stack(exists: Callable[[str], bool], read: Callable[[str], str]) -> Tuple[bool, str]:
    """Is this the supported default stack? Input: exists/read callables (repo-relative). Returns: (supported,
    label). Supported = a package.json with a JS/TS framework or TypeScript; anything else → not supported."""
    if not exists("package.json"):
        for f, lang in (("requirements.txt", "Python"), ("pyproject.toml", "Python"), ("go.mod", "Go"),
                        ("Gemfile", "Ruby"), ("composer.json", "PHP"), ("Cargo.toml", "Rust")):
            if exists(f):
                return False, f"not supported for this stack ({lang}) — only the default JavaScript/TypeScript stack is checked"
        return False, "not supported for this stack (no package.json) — only the default JavaScript/TypeScript stack is checked"
    try:
        pkg = json.loads(read("package.json") or "{}")
    except Exception:
        pkg = {}
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    if any(k in deps for k in ("next", "react", "typescript", "express", "@supabase/supabase-js")) or exists("tsconfig.json"):
        return True, "javascript/typescript (default stack)"
    return False, "not supported for this stack (package.json without a recognised JS/TS framework)"


def _norm(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def module_of(path: str, modules: List[Dict]) -> Optional[str]:
    """The module whose folder holds `path` (longest folder wins). Input: path, map modules. Returns: name/None."""
    best, best_len = None, -1
    for m in modules:
        f = _norm(str(m.get("folder") or "")).rstrip("/") + "/"
        if f != "/" and (_norm(path) + "/").startswith(f) and len(f) > best_len:
            best, best_len = m.get("name"), len(f)
    return best


def door_files(module_map: Dict) -> Dict[str, str]:
    """{shared job: door file} for the declared (not n/a) doors."""
    out: Dict[str, str] = {}
    for d in module_map.get("doors") or []:
        if isinstance(d, dict) and d.get("job") and not d.get("not_applicable") and d.get("file"):
            out.setdefault(d["job"], _norm(d["file"]))
    return out


def count_duplicates(files: Dict[str, str], module_map: Dict, styling_source: str = "") -> Dict[str, Dict]:
    """Gate 1 counts. Input: {path: body} of every code file, the map, the styling source path. Returns:
    {job: {count, paths}} — files OUTSIDE the job's door file that match the job's pattern."""
    doors = door_files(module_map)
    out: Dict[str, Dict] = {}
    for job, pats in JOB_PATTERNS.items():
        door = doors.get(job)
        paths = sorted(p for p, body in files.items()
                       if p != door and p != _norm(styling_source) and any(pt.search(body) for pt in pats))
        out[job] = {"count": len(paths), "paths": paths[:200]}
    return out


def ratchet(current: Dict[str, Dict], allowed: Dict[str, int]) -> List[str]:
    """Gate 1 verdict. Input: current counts, the BASE allowance. Returns: one reason per job above its allowance."""
    return [f"{job}: {v['count']} outside its door (allowed {int(allowed.get(job, 0))}) — a second copy was added; "
            f"use the door ({', '.join(v['paths'][:5])})"
            for job, v in current.items() if v["count"] > int(allowed.get(job, 0))]


def oversize(lines_now: Dict[str, int], lines_base: Dict[str, int], limit: int = SIZE_LIMIT) -> List[str]:
    """Gate 2. Input: {path: lines} now and at base (absent = new file). Returns: paths that fail."""
    bad = []
    for p, n in sorted(lines_now.items()):
        if n > limit:
            b = lines_base.get(p)
            if b is None or n > b:
                bad.append(f"{p} ({n} lines; limit {limit}{'' if b is None else f'; was {b} — may only shrink'})")
    return bad


def resolve_import(src: str, spec: str, exists: Callable[[str], bool], alias_root: str = "") -> Optional[str]:
    """Resolve a relative or '@/' import from `src` to a repo path (or None for a package import)."""
    if spec.startswith("@/"):
        base = _norm(os.path.join(alias_root, spec[2:]))
    elif spec.startswith("."):
        base = _norm(os.path.normpath(os.path.join(os.path.dirname(src), spec)))
    else:
        return None
    for cand in [base] + [base + e for e in CODE_EXT] + [base + "/index" + e for e in CODE_EXT]:
        if exists(cand):
            return cand
    return base


def cross_imports(files: Dict[str, str], module_map: Dict, exists: Callable[[str], bool], alias_root: str = "") -> List[str]:
    """Gate 3. Input: {path: body}, the map, exists, the '@/' root. Returns: "a -> b" edges that reach into another
    module other than through one of its door files."""
    modules = [m for m in module_map.get("modules") or [] if isinstance(m, dict)]
    doors_by_module: Dict[str, set] = {}
    for d in module_map.get("doors") or []:
        if isinstance(d, dict) and d.get("module") and d.get("file") and not d.get("not_applicable"):
            doors_by_module.setdefault(d["module"], set()).add(_norm(d["file"]))
    bad = []
    for src, body in sorted(files.items()):
        a = module_of(src, modules)
        if a is None:
            continue
        for spec in _IMPORT_RE.findall(body):
            tgt = resolve_import(src, spec, exists, alias_root)
            if not tgt:
                continue
            b = module_of(tgt, modules)
            if b is None or b == a:
                continue
            if tgt not in doors_by_module.get(b, set()):
                bad.append(f"{src} -> {tgt} (module '{a}' reaches into '{b}' outside its door)")
    return bad


def run(base: str, read_now: Callable[[str], str], exists_now: Callable[[str], bool],
        read_base: Callable[[str], Optional[str]], code_files: List[str], styling_source: str = "",
        alias_root: str = "") -> Dict:
    """All three gates. Returns the `modular` payload block: {status: ok|fail|not_supported, reason?, stack,
    duplicates, duplicate_failures, oversize, cross_imports, not_pattern_checked, module_map_sha256,
    module_map_changed}. Never a false pass: a missing/invalid map FAILS; an unsupported stack is labelled."""
    supported, stack = detect_stack(exists_now, read_now)
    block: Dict = {"stack": stack, "not_pattern_checked": list(NOT_PATTERN_CHECKED)}
    raw_map = read_now(MAP_PATH) if exists_now(MAP_PATH) else None
    block["module_map_sha256"] = hashlib.sha256(raw_map.encode()).hexdigest() if raw_map else None
    base_map = read_base(MAP_PATH)
    block["module_map_changed"] = (raw_map or "") != (base_map or "")
    if not supported:
        block.update({"status": "not_supported", "reason": stack})
        return block
    try:
        module_map = json.loads(raw_map) if raw_map else None
    except Exception:
        module_map = None
    if not isinstance(module_map, dict):
        block.update({"status": "fail", "reason": f"{MAP_PATH} is missing or not valid JSON — the approved module map "
                                                  f"must be committed (written at setup)"})
        return block
    files = {p: (read_now(p) or "") for p in code_files
             if p.endswith(CODE_EXT) and not p.startswith(_SKIP_DIRS) and exists_now(p)}
    dups = count_duplicates(files, module_map, styling_source)
    try:
        allowed = json.loads(read_base(DUP_PATH) or "{}")
    except Exception:
        allowed = {}
    dup_fail = ratchet(dups, allowed if isinstance(allowed, dict) else {})
    lines_now = {p: b.count("\n") + (0 if b.endswith("\n") or not b else 1) for p, b in files.items()}
    lines_base = {}
    for p in lines_now:
        bb = read_base(p)
        if bb is not None:
            lines_base[p] = bb.count("\n") + (0 if bb.endswith("\n") or not bb else 1)
    big = oversize(lines_now, lines_base)
    xi = cross_imports(files, module_map, exists_now, alias_root)
    block.update({"duplicates": dups, "duplicate_failures": dup_fail, "oversize": big[:200],
                  "cross_imports": xi[:200]})
    block["status"] = "fail" if (dup_fail or big or xi) else "ok"
    return block


def _git_show(base: str, path: str) -> Optional[str]:
    """Read `path` at commit `base` (None if absent)."""
    try:
        return subprocess.run(["git", "show", f"{base}:{path}"], capture_output=True, text=True, check=True).stdout
    except Exception:
        return None


def _alias_root() -> str:
    """The '@/' alias root from tsconfig.json compilerOptions.paths ('@/*' → './src/*' gives 'src')."""
    try:
        cfg = json.loads(open("tsconfig.json", encoding="utf-8").read())
        tgt = ((cfg.get("compilerOptions") or {}).get("paths") or {}).get("@/*", ["./*"])[0]
        return _norm(tgt.rstrip("*").rstrip("/"))
    except Exception:
        return ""


def main() -> None:
    """CLI: python module_gates.py --base <sha> --styling-path <p> --out modular.json (run at the repo root)."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--styling-path", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.splitlines()

    def read_now(p: str) -> str:
        try:
            return open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            return ""

    block = run(a.base, read_now, os.path.exists, lambda p: _git_show(a.base, p), tracked, a.styling_path,
                _alias_root())
    json.dump(block, open(a.out, "w", encoding="utf-8"))


if __name__ == "__main__":
    main()
