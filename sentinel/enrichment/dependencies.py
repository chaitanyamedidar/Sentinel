from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "pyproject.toml",
}

_REQ_NAME_VERSION = re.compile(r"^\s*([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*==\s*([A-Za-z0-9_.!+*-]+)")
_PEP508_NAME_VERSION = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.!+*-]+)")


def parse_dependency_files(files: Mapping[str, str]) -> list[dict[str, str]]:
    refs: dict[tuple[str, str, str], dict[str, str]] = {}
    for path, content in files.items():
        normalized = path.replace("\\", "/")
        name = normalized.rsplit("/", 1)[-1]
        if name == "package.json":
            _add_all(refs, _parse_package_json(content))
        elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
            _add_all(refs, _parse_package_lock(content))
        elif name == "requirements.txt":
            _add_all(refs, _parse_requirements(content))
        elif name == "pyproject.toml":
            _add_all(refs, _parse_pyproject(content))
    return sorted(refs.values(), key=lambda item: (item["ecosystem"], item["name"], item["version"]))


def is_dependency_file(path: str) -> bool:
    return path.replace("\\", "/").rsplit("/", 1)[-1] in DEPENDENCY_FILES


def dependency_diff_hash(packages: list[Mapping[str, str]]) -> str:
    import hashlib

    payload = json.dumps(
        sorted(
            {
                "ecosystem": str(item.get("ecosystem", "")).lower(),
                "name": str(item.get("name", "")),
                "version": str(item.get("version", "")),
            }
            for item in packages
        ),
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _add_all(target: dict[tuple[str, str, str], dict[str, str]], refs: list[dict[str, str]]) -> None:
    for ref in refs:
        key = (ref["ecosystem"], ref["name"], ref["version"])
        target[key] = ref


def _parse_package_json(content: str) -> list[dict[str, str]]:
    payload = json.loads(content)
    refs: list[dict[str, str]] = []
    for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (payload.get(group) or {}).items():
            version = _clean_npm_version(str(spec))
            if version:
                refs.append({"name": str(name), "version": version, "ecosystem": "npm"})
    return refs


def _parse_package_lock(content: str) -> list[dict[str, str]]:
    payload = json.loads(content)
    refs: list[dict[str, str]] = []
    for path, package in (payload.get("packages") or {}).items():
        if not path or not isinstance(package, dict) or not package.get("version"):
            continue
        name = str(package.get("name") or path.rsplit("node_modules/", 1)[-1])
        refs.append({"name": name, "version": str(package["version"]), "ecosystem": "npm"})
    for name, package in (payload.get("dependencies") or {}).items():
        if isinstance(package, dict) and package.get("version"):
            refs.append({"name": str(name), "version": str(package["version"]), "ecosystem": "npm"})
    return refs


def _parse_requirements(content: str) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        match = _REQ_NAME_VERSION.match(line)
        if match:
            refs.append({"name": _strip_extras(match.group(1)), "version": match.group(2), "ecosystem": "pypi"})
    return refs


def _parse_pyproject(content: str) -> list[dict[str, str]]:
    payload = tomllib.loads(content)
    refs: list[dict[str, str]] = []
    for spec in payload.get("project", {}).get("dependencies") or []:
        parsed = _parse_pep508_pin(str(spec))
        if parsed:
            refs.append(parsed)
    for group in (payload.get("project", {}).get("optional-dependencies") or {}).values():
        for spec in group or []:
            parsed = _parse_pep508_pin(str(spec))
            if parsed:
                refs.append(parsed)
    for group in (payload.get("dependency-groups") or {}).values():
        for spec in group or []:
            parsed = _parse_pep508_pin(str(spec))
            if parsed:
                refs.append(parsed)
    return refs


def _parse_pep508_pin(spec: str) -> dict[str, str] | None:
    match = _PEP508_NAME_VERSION.match(spec.split(";", 1)[0].strip())
    if not match:
        return None
    return {"name": match.group(1), "version": match.group(2), "ecosystem": "pypi"}


def _clean_npm_version(spec: str) -> str:
    value = spec.strip()
    if not value or value.startswith(("workspace:", "file:", "link:", "git+", "http://", "https://")):
        return ""
    value = value.split("||", 1)[0].strip()
    value = re.sub(r"^[~^<>=\s]+", "", value)
    value = value.split()[0] if value else ""
    return value if re.match(r"^\d", value) else ""


def _strip_extras(name: str) -> str:
    return name.split("[", 1)[0]
