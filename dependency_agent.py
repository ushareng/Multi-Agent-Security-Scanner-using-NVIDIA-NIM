"""
agents/dependency_agent.py
Dependency Agent — resolves direct and transitive dependencies,
maps to known CVEs via OSV (open-source vulnerability DB, free API),
and stores risk-ranked dependency graph in shared memory.
"""

import os
import json
import requests
import toml
from pathlib import Path
from memory_store import MemoryStore

# OSV.dev is a free, open-source vulnerability database by Google
OSV_API = "https://api.osv.dev/v1/query"

MANIFEST_FILES = {
    "requirements.txt": "pypi",
    "requirements.in": "pypi",
    "Pipfile": "pypi",
    "pyproject.toml": "pypi",
    "package.json": "npm",
    "yarn.lock": "npm",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "Gemfile": "rubygems",
    "Gemfile.lock": "rubygems",
    "composer.json": "packagist",
}


class DependencyAgent:
    def __init__(self, store: MemoryStore):
        self.store = store

    def run(self, target_path: str) -> dict:
        """
        Walk target path for manifest files, extract dependencies,
        query OSV for known CVEs, return risk-ranked dependency map.
        """
        print("[Dependency] Scanning dependency manifests...")
        all_deps = {}

        for dirpath, _, filenames in os.walk(target_path):
            # Skip vendor/build dirs
            if any(skip in dirpath for skip in ["node_modules", "vendor", ".git"]):
                continue
            for fname in filenames:
                if fname in MANIFEST_FILES:
                    ecosystem = MANIFEST_FILES[fname]
                    fpath = os.path.join(dirpath, fname)
                    deps = self._parse_manifest(fpath, fname, ecosystem)
                    all_deps.update(deps)

        print(f"[Dependency] Found {len(all_deps)} dependencies, querying OSV...")
        cve_results = self._query_osv_bulk(all_deps)

        self.store.dependency_graph = all_deps
        self.store.known_cves = cve_results

        vulnerable_count = sum(1 for v in cve_results.values() if v)
        print(f"[Dependency] {vulnerable_count} dependencies with known CVEs")
        return cve_results

    def _parse_manifest(self, fpath: str, fname: str, ecosystem: str) -> dict:
        deps = {}
        try:
            if fname == "requirements.txt" or fname == "requirements.in":
                deps = self._parse_requirements_txt(fpath, ecosystem)
            elif fname == "pyproject.toml":
                deps = self._parse_pyproject_toml(fpath, ecosystem)
            elif fname == "package.json":
                deps = self._parse_package_json(fpath, ecosystem)
            elif fname == "go.mod":
                deps = self._parse_go_mod(fpath, ecosystem)
            elif fname == "Gemfile.lock":
                deps = self._parse_gemfile_lock(fpath, ecosystem)
        except Exception as e:
            print(f"[Dependency] Warning: could not parse {fpath}: {e}")
        return deps

    def _parse_requirements_txt(self, fpath: str, ecosystem: str) -> dict:
        deps = {}
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle ==, >=, <=, ~=, !=
                for op in ["==", ">=", "<=", "~=", "!="]:
                    if op in line:
                        name, version = line.split(op, 1)
                        version = version.split(",")[0].strip()
                        deps[name.strip()] = {"version": version, "ecosystem": ecosystem}
                        break
                else:
                    deps[line] = {"version": "unknown", "ecosystem": ecosystem}
        return deps

    def _parse_pyproject_toml(self, fpath: str, ecosystem: str) -> dict:
        deps = {}
        try:
            data = toml.load(fpath)
            project_deps = data.get("project", {}).get("dependencies", [])
            for dep in project_deps:
                for op in [">=", "<=", "==", "~="]:
                    if op in dep:
                        name, version = dep.split(op, 1)
                        deps[name.strip()] = {"version": version.strip(), "ecosystem": ecosystem}
                        break
                else:
                    deps[dep.strip()] = {"version": "unknown", "ecosystem": ecosystem}
        except Exception:
            pass
        return deps

    def _parse_package_json(self, fpath: str, ecosystem: str) -> dict:
        deps = {}
        with open(fpath) as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                clean_version = version.lstrip("^~>=")
                deps[name] = {"version": clean_version, "ecosystem": ecosystem}
        return deps

    def _parse_go_mod(self, fpath: str, ecosystem: str) -> dict:
        deps = {}
        with open(fpath) as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    line = line.replace("require ", "").strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        deps[parts[0]] = {"version": parts[1], "ecosystem": ecosystem}
        return deps

    def _parse_gemfile_lock(self, fpath: str, ecosystem: str) -> dict:
        deps = {}
        with open(fpath) as f:
            in_specs = False
            for line in f:
                if "  specs:" in line:
                    in_specs = True
                    continue
                if in_specs and line.strip() == "":
                    in_specs = False
                if in_specs and line.startswith("    ") and "(" in line:
                    parts = line.strip().split(" (")
                    if len(parts) == 2:
                        name = parts[0].strip()
                        version = parts[1].rstrip(")")
                        deps[name] = {"version": version, "ecosystem": ecosystem}
        return deps

    def _query_osv_bulk(self, deps: dict) -> dict:
        """Query OSV.dev API for each dependency. Returns {pkg_name: [cve_list]}."""
        results = {}
        for pkg_name, pkg_info in deps.items():
            if pkg_info["version"] == "unknown":
                continue
            try:
                payload = {
                    "version": pkg_info["version"],
                    "package": {
                        "name": pkg_name,
                        "ecosystem": self._normalize_ecosystem(pkg_info["ecosystem"]),
                    },
                }
                resp = requests.post(OSV_API, json=payload, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulns", [])
                    if vulns:
                        results[pkg_name] = [
                            {
                                "id": v.get("id"),
                                "summary": v.get("summary", ""),
                                "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                            }
                            for v in vulns
                        ]
                    else:
                        results[pkg_name] = []
            except Exception as e:
                results[pkg_name] = []

        return results

    def _normalize_ecosystem(self, ecosystem: str) -> str:
        mapping = {
            "pypi": "PyPI",
            "npm": "npm",
            "go": "Go",
            "maven": "Maven",
            "rubygems": "RubyGems",
            "packagist": "Packagist",
        }
        return mapping.get(ecosystem, ecosystem)
