#!/usr/bin/env python3
"""F22(b)/F25 (Strategy S347 §2b, S348 §3, D-3296, D-315) — the signed check fails when the repository tries to silence it.

DESTINATION: Hepherus-Forge/checks/scripts/suppression_gate.py (published + pinned with the reusable workflow).
It runs in the customer's own GitHub Actions runner, in the job that never runs the project's code, and writes
suppression.json (a count and PATHS only, never a value) and vuln.json (advisory counts).

Two things, both fail closed:
  1. SUPPRESSION: a tracked file or key that makes an audit tool ignore, allow or lower a finding, or that sends npm
     anywhere but the public registry, fails the check, whatever Mocca, a worker or a customer said.
  2. THE AUDIT ITSELF: npm audits a COPY of package.json and the lockfile in a clean folder, with no .npmrc of the project
     or the user and no npm_config_* variable, at the public registry, every dependency group. Declared packages without a
     lockfile, or an answer that cannot be read (after 3 tries), is a failure and never "0 advisories".

A lockfile entry must be the registry's own archive of the package and version it names; anything else fails.
Standard library only. NOT covered: a suppression in a tool this list does not name; code copied into the repository by hand;
yarn and pnpm lockfiles, and private registries (the default stack uses npm and the public registry: such a repository fails).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# A file that exists only to make an audit tool ignore something. Any folder, any letter case, whatever it contains.
_FILES = re.compile(r"^(?:\.nsprc|\.auditrc(?:\.json)?|\.?audit-ci\.(?:json|jsonc|json5)|\.?audit-ci|\.auditignore"
                    r"|\.npmauditrc|audit-resolve\.json|\.trivyignore(?:\.ya?ml)?|osv-scanner\.toml|\.snyk|\.grype\.ya?ml"
                    r"|\.better-npm-audit\.json)$", re.I)
_RC_FILES = {".npmrc", ".pnpmrc"}
# the ONLY .npmrc keys a project may set: none of them changes what is audited or where npm asks
_RC_OK = re.compile(r"^(?:save-exact|save-prefix|save|fund|engine-strict|legacy-peer-deps|strict-peer-deps|loglevel|progress|message"
                    r"|update-notifier|prefer-offline|prefer-dedupe|init-[\w.-]+|node-version|lockfile-version|ignore-scripts"
                    r"|auto-install-peers|strict-peer-dependencies|shamefully-hoist|node-linker|public-hoist-pattern(?:\[\])?"
                    r"|@[\w.-]+:registry|//[^=]+:(?:_authToken|always-auth))$", re.I)
_PUBLIC = {"https://registry.npmjs.org", "https://registry.yarnpkg.com"}
_PKG_KEYS = {"auditConfig", "audit-ci", "better-npm-audit", "nsp"}
_PKG_TOOLS = {"audit-ci", "better-npm-audit", "npm-audit-resolver", "nsp"}
_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_YARN = re.compile(r"^\s*(?:npmAuditExcludePackages|npmAuditIgnoreAdvisories|npmRegistryServer)\b", re.M)
_PNPM_WS = re.compile(r"^\s*(?:auditConfig|ignoreCves|ignoreGhsas)\s*:", re.M)
_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
_SKIP = {"node_modules", ".hepherus-checks"}
_SAMPLES = {"fixtures", "__fixtures__", "examples", "example", "testdata", "templates"}
_RANGE = re.compile(r"^[\w.^~<>=|* +-]+$")          # a semver range or a registry tag: "16.4.6", "^1 || ^2", "latest", "*"


def _json(text: Optional[str]) -> Any:
    """Parse JSON. Input: the text. Returns: the value, or None when it cannot be read (nested too deep included)."""
    try:
        return json.loads(text or "")
    except (ValueError, RecursionError):
        return None


def _rc_reason(text: str) -> bool:
    """Whether an .npmrc text sets a key outside the allowed list, or another registry. Input: the text. Returns: bool."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        key, _, value = s.partition("=")
        key, value = key.strip(), value.strip().strip("'\"").rstrip("/")
        if key.lower() == "registry":
            if value not in _PUBLIC:
                return True
        elif not _RC_OK.match(key):
            return True
    return False


def _lock_reason(text: str, workspaces: bool) -> bool:
    """Whether a lockfile holds an entry that is not the public registry's archive of that package and version (a git or web
    address, another archive, a link outside a workspace). Input: the lockfile text, whether the root has workspaces.
    Returns: bool (an unreadable lockfile is left to the audit, which then cannot be read)."""
    d = _json(text)
    pkgs = d.get("packages") if isinstance(d, dict) else None
    if not isinstance(pkgs, dict):
        return isinstance(d, dict) and bool(d.get("dependencies"))          # an old lockfile format: not readable here
    for key, e in pkgs.items():
        if key == "" or not isinstance(e, dict):
            continue
        if e.get("link"):
            if not workspaces:
                return True
            continue
        if "node_modules/" not in key or e.get("inBundle"):
            continue                                                       # a workspace folder, or inside its parent's archive
        name, version, url = str(e.get("name") or key.rsplit("node_modules/", 1)[-1]), str(e.get("version") or ""), e.get("resolved")
        tail = f"/{name}/-/{name.rsplit('/', 1)[-1]}-{version.split('+', 1)[0]}.tgz"
        if url is not None and url not in {base + tail for base in _PUBLIC}:
            return True
        if url is None and not e.get("extraneous") and not version:
            return True
    return False


def _swap_reason(node: Any, names: List[str], override: bool, workspaces: bool = False) -> bool:
    """Whether a tree of specs replaces a package by something the registry's advisories do not cover: another package
    ("npm:other@1"), a git or web address, or (in an override) a local stub. Input: the node, the names above it, whether it
    is an overrides/resolutions tree. Returns: bool."""
    if isinstance(node, dict):
        return any(_swap_reason(v, names + [str(k)], override, workspaces) for k, v in node.items())
    if not isinstance(node, str) or not names:
        return False
    if node.startswith("npm:"):
        other = re.sub(r"(?<=.)@[^@/]*$", "", node[4:])
        mine = re.sub(r"(?<=.)@[^@/]*$", "", re.split(r">|/\*\*/", names[-1])[-1])
        return other != mine
    if override:
        return not (_RANGE.match(node) or node.startswith("$") or node == "")
    return not (_RANGE.match(node) or node == "" or (workspaces and node.startswith(("file:", "link:", "workspace:", "./", "../"))))


def _pkg_reason(text: str, workspaces: bool = False) -> bool:
    """Whether a package.json configures or installs an audit silencer, or replaces a package by something without advisories.
    Unreadable JSON counts. Input: the text, whether the root has workspaces (local packages are then normal). Returns: bool."""
    d = _json(text)
    if not isinstance(d, dict):
        return True
    pnpm = d.get("pnpm") if isinstance(d.get("pnpm"), dict) else {}
    deps = {k: d[k] for k in _DEP_KEYS if isinstance(d.get(k), dict)}
    names = {n for block in deps.values() for n in block}
    if _PKG_KEYS & set(d) or "auditConfig" in pnpm or _PKG_TOOLS & names:
        return True
    try:
        return (any(_swap_reason(t, [], True) for t in (d.get("overrides"), d.get("resolutions"), pnpm.get("overrides")))
                or any(_swap_reason(block, [], False, workspaces) for block in deps.values()))
    except RecursionError:
        return True


def scan(files: Dict[str, str]) -> List[str]:
    """The paths that silence an audit. Input: {repo path: text} of every tracked candidate file. Returns: sorted paths."""
    out = []
    root = _json(files.get("package.json"))
    ws = isinstance(root, dict) and bool(root.get("workspaces"))
    for path, text in files.items():
        name = path.rsplit("/", 1)[-1]
        if (_FILES.match(name) or (name.lower() in _RC_FILES and _rc_reason(text))
                or (name == "package.json" and _pkg_reason(text, ws))
                or (name in _LOCKS and _lock_reason(text, ws))
                or (name.lower() in (".yarnrc.yml", ".yarnrc.yaml") and _YARN.search(text))
                or (name.lower() in ("pnpm-workspace.yaml", "pnpm-workspace.yml") and _PNPM_WS.search(text))):
            out.append(path)
    return sorted(out)


def is_candidate(path: str) -> bool:
    """Whether a tracked path is worth reading: not in node_modules, and a package.json only outside sample folders.
    Input: the path. Returns: bool."""
    parts = path.split("/")
    name = parts[-1].lower()
    if _SKIP & set(parts):
        return False
    if name == "package.json" or name in _LOCKS:
        return not _SAMPLES & set(parts[:-1])
    return bool(_FILES.match(name)) or name in _RC_FILES or name in (
        ".yarnrc.yml", ".yarnrc.yaml", "pnpm-workspace.yaml", "pnpm-workspace.yml")


def _declares(text: Optional[str]) -> Optional[bool]:
    """Whether a package.json declares packages. Input: the text. Returns: bool, None when it cannot be read."""
    d = _json(text)
    if not isinstance(d, dict):
        return None
    return any(isinstance(d.get(k), dict) and d[k] for k in _DEP_KEYS)


def _in_workspaces(folder: str, root: Any) -> bool:
    """Whether a folder matches the root's `workspaces` patterns ("*" stays inside one folder name, "**" does not).
    Input: the folder, the parsed root package.json. Returns: bool."""
    ws = root.get("workspaces") if isinstance(root, dict) else None
    pats = ws.get("packages") if isinstance(ws, dict) else ws
    for pat in pats if isinstance(pats, list) else []:
        rx = re.escape(str(pat).strip("/").replace("./", "", 1) if str(pat).startswith("./") else str(pat).strip("/"))
        if re.fullmatch(rx.replace(r"\*\*", ".*").replace(r"\*", "[^/]*"), folder):
            return True
    return False


def audit_targets(files: Dict[str, str], tracked: List[str]) -> Tuple[str, List[str]]:
    """Which folders are audited. Input: the candidate files, every tracked path. Returns: ("ok" | "none" | "no_lockfile" |
    "unreadable", folders: "" is the root). A folder that declares packages needs a lockfile of its own, or a root that has
    one and names workspaces."""
    root = _json(files.get("package.json"))
    has = set(tracked)
    root_lock = any(n in has for n in _LOCKS)
    targets: List[str] = []
    for path in sorted(p for p in files if p.rsplit("/", 1)[-1] == "package.json"):
        folder = path[:-len("package.json")].rstrip("/")
        declares = _declares(files[path])
        if declares is None:
            return "unreadable", []
        lock = any((folder + "/" if folder else "") + n in has for n in _LOCKS)
        if lock:
            targets.append(folder)
        elif folder == "" and isinstance(root, dict) and root.get("workspaces"):
            return "no_lockfile", []
        elif declares and not (folder and root_lock and _in_workspaces(folder, root)):
            return "no_lockfile", []
    return ("ok" if targets else "none"), targets


def counts_of(audit_json: Optional[str]) -> Optional[Dict[str, int]]:
    """npm's counts. Input: npm's JSON. Returns: {critical, high, moderate, low} or None when it is not a readable answer."""
    try:
        v = _json(audit_json)["metadata"]["vulnerabilities"]
        return {k: int(v[k]) for k in ("critical", "high", "moderate", "low")}
    except (KeyError, TypeError, ValueError):
        return None


def npm_audit(folder: str, tracked: List[str]) -> Optional[str]:
    """npm's JSON answer for one folder's lockfile, from a clean copy: package.json files and the lockfile only, no .npmrc,
    no npm_config_* variable, the public registry, every dependency group; 3 tries. Input: the folder ("" = root), every
    tracked path. Returns: the last JSON text, None when npm did not answer."""
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        return None
    env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_") and not k.lower().endswith("_proxy")}
    pre = folder + "/" if folder else ""
    with tempfile.TemporaryDirectory() as tmp:
        # two names that do not exist (npm refuses one path for both)
        env.update({"npm_config_userconfig": os.path.join(tmp, "no-user-npmrc"), "npm_config_globalconfig": os.path.join(tmp, "no-global-npmrc")})
        for p in tracked:
            if p.startswith(pre) and not _SKIP & set(p.split("/")) and (
                    p in (pre + "package-lock.json", pre + "npm-shrinkwrap.json") or p.endswith("/package.json") or p == pre + "package.json"):
                if os.path.islink(p) or not os.path.isfile(p):
                    return None
                dest = os.path.join(tmp, *p[len(pre):].split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copyfile(p, dest)
        last = None
        for attempt in range(3):
            if attempt:
                time.sleep(10)
            try:
                r = subprocess.run([npm, "audit", "--json", "--registry=https://registry.npmjs.org/", "--include=prod", "--include=dev",
                                    "--include=optional", "--include=peer"], cwd=tmp, env=env, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=120)
                last = r.stdout
            except subprocess.TimeoutExpired:
                last = None
            if counts_of(last) is not None:
                return last
            d = _json(last)
            if isinstance(d, dict) and isinstance(d.get("error"), dict) and str(d["error"].get("code") or "").startswith(("ENOLOCK", "EJSONPARSE", "EUSAGE")):
                return last                         # the repository's own file is at fault: trying again changes nothing
        return last


def judge(files: Dict[str, str], tracked: List[str], audit: Callable[[str, List[str]], Optional[str]]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """The whole gate. Input: candidate files, tracked paths, the audit function. Returns: (suppression block, counts)."""
    total = {k: 0 for k in ("critical", "high", "moderate", "low")}
    paths = scan(files)
    state, targets = audit_targets(files, tracked)
    for folder in targets:
        got = counts_of(audit(folder, tracked))
        if got is None:
            state = "unreadable"
            break
        total = {k: total[k] + got[k] for k in total}
    bad = bool(paths) or state in ("no_lockfile", "unreadable")
    return {"status": "fail" if bad else "ok", "count": len(paths), "paths": paths[:500], "audit": state}, total


def main() -> None:
    """Read the repository; write suppression.json and vuln.json. Returns: None."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--vuln-out", default="vuln.json")
    ap.add_argument("--out", default="suppression.json")
    a = ap.parse_args()
    tracked = [p for p in subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.decode(
        "utf-8", "replace").split("\0") if p]
    files: Dict[str, str] = {}
    for p in tracked:
        if is_candidate(p):
            try:
                with open(p, encoding="utf-8-sig", errors="replace") as fh:
                    files[p] = fh.read()
            except OSError:
                files[p] = "unreadable=1"           # not JSON, and not an allowed .npmrc key: named either way
    block, counts = judge(files, tracked, npm_audit)
    for path, value in ((a.vuln_out, counts), (a.out, block)):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(value, fh)
    print("suppression:", json.dumps(block), "advisories:", json.dumps(counts))


if __name__ == "__main__":
    main()
