#!/usr/bin/env python3
"""
osv-audit - check your project's dependencies against the OSV.dev
database of known vulnerabilities, and show which versions fix them.

Pure Python standard library. It reads a lockfile you point it at, then
sends the package names and versions to the public OSV.dev API
(https://osv.dev) and reports any known vulnerabilities. It does not
execute your project, install anything, or send any other data.

Supported inputs:
    requirements.txt   (pinned "pkg==1.2.3" lines)      ecosystem PyPI
    package-lock.json  (npm v2/v3 lockfiles)            ecosystem npm

Examples:
    osv_audit.py requirements.txt
    osv_audit.py package-lock.json --format json
    osv_audit.py requirements.txt --fail-on-vuln        # exit 2 if any vuln
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict

__version__ = "1.0.0"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
USER_AGENT = f"osv-audit/{__version__} (+https://github.com/Zasnit1/osv-audit)"


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str


@dataclass
class Vuln:
    package: str
    version: str
    ecosystem: str
    id: str
    summary: str
    fixed: str


# --------------------------------------------------------------------------- parsing

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)")


def parse_requirements(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            pkgs.append(Package(m.group(1), m.group(2), "PyPI"))
    return pkgs


def parse_package_lock(text: str) -> list[Package]:
    data = json.loads(text)
    out: dict[tuple[str, str], Package] = {}
    # npm v2/v3: "packages" keyed by path; v1: "dependencies" nested
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            out[(name, ver)] = Package(name, ver, "npm")

    def walk(deps: dict):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.setdefault((name, meta["version"]), Package(name, meta["version"], "npm"))
                walk(meta.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return list(out.values())


def load_packages(path: str, text: str) -> list[Package]:
    low = path.lower()
    if low.endswith(".json") or "package-lock" in low:
        return parse_package_lock(text)
    return parse_requirements(text)


# --------------------------------------------------------------------------- OSV query

def _post(url: str, payload: dict, timeout: float) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fixed_version(vuln_detail: dict, pkg: Package) -> str:
    """Pull the first 'fixed' version from an OSV record's affected ranges."""
    for aff in vuln_detail.get("affected", []):
        p = aff.get("package", {})
        if p.get("name") != pkg.name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return ""


def query_osv(pkgs: list[Package], timeout: float, fetch=_post, fetch_one=_get) -> list[Vuln]:
    """Query OSV for a list of packages. `fetch`/`fetch_one` are injectable for tests."""
    if not pkgs:
        return []
    queries = [{"version": p.version, "package": {"name": p.name, "ecosystem": p.ecosystem}} for p in pkgs]
    results = fetch(OSV_BATCH_URL, {"queries": queries}, timeout).get("results", [])
    out: list[Vuln] = []
    detail_cache: dict[str, dict] = {}
    for pkg, res in zip(pkgs, results):
        for v in res.get("vulns", []) or []:
            vid = v.get("id", "")
            if vid and vid not in detail_cache:
                try:
                    detail_cache[vid] = fetch_one(OSV_VULN_URL + vid, timeout)
                except (urllib.error.URLError, TimeoutError, ValueError):
                    detail_cache[vid] = {}
            detail = detail_cache.get(vid, {})
            out.append(Vuln(pkg.name, pkg.version, pkg.ecosystem, vid,
                            detail.get("summary", "").strip() or "(no summary)",
                            fixed_version(detail, pkg)))
    return out


# --------------------------------------------------------------------------- output

def render_text(vulns: list[Vuln], total: int) -> str:
    if not vulns:
        return f"Checked {total} package(s). No known vulnerabilities found."
    lines = [f"Checked {total} package(s). {len(vulns)} known vulnerabilit"
             f"{'y' if len(vulns) == 1 else 'ies'} found:\n"]
    for v in sorted(vulns, key=lambda x: (x.package, x.id)):
        fix = f"fixed in {v.fixed}" if v.fixed else "no fixed version listed"
        lines.append(f"  {v.package} {v.version} ({v.ecosystem})")
        lines.append(f"    {v.id}: {v.summary}")
        lines.append(f"    -> {fix}   https://osv.dev/vulnerability/{v.id}")
    return "\n".join(lines)


def render_json(vulns: list[Vuln]) -> str:
    return json.dumps([asdict(v) for v in vulns], indent=2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="osv_audit", description="Check project dependencies against the OSV.dev vulnerability database.")
    p.add_argument("lockfile", help="requirements.txt (PyPI) or package-lock.json (npm).")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--fail-on-vuln", action="store_true", help="Exit code 2 if any vulnerability is found (for CI).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open(args.lockfile, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        print(f"Cannot read {args.lockfile}: {e}", file=sys.stderr)
        return 1
    try:
        pkgs = load_packages(args.lockfile, text)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Could not parse {args.lockfile}: {e}", file=sys.stderr)
        return 1
    if not pkgs:
        print("No pinned dependencies found to check.", file=sys.stderr)
        return 0
    try:
        vulns = query_osv(pkgs, args.timeout)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"OSV query failed: {e}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(render_json(vulns))
    else:
        print(render_text(vulns, len(pkgs)))
    return 2 if (args.fail_on_vuln and vulns) else 0


if __name__ == "__main__":
    sys.exit(main())
