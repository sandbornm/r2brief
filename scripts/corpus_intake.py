#!/usr/bin/env python3
"""Fetch or verify pinned benchmark inputs without unpacking or executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "corpora" / "manifest.json"
DEFAULT_OUTPUT = PROJECT_ROOT / ".r2b-corpus"
CHUNK_SIZE = 1024 * 1024


class IntakeError(RuntimeError):
    pass


def _safe_id(value: Any) -> str:
    text = str(value or "")
    if not text or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-." for char in text):
        raise IntakeError(f"unsafe dataset id: {text!r}")
    return text


def _safe_filename(value: Any) -> str:
    text = str(value or "")
    if not text or Path(text).name != text or text in {".", ".."}:
        raise IntakeError(f"unsafe filename: {text!r}")
    return text


def _validate_url(url: str, allowed_hosts: set[str]) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise IntakeError(f"only HTTPS sources are allowed: {url}")
    if parsed.username or parsed.password:
        raise IntakeError(f"credentials are forbidden in corpus URLs: {url}")
    if parsed.hostname.lower() not in allowed_hosts:
        raise IntakeError(f"source host is not allowlisted: {parsed.hostname}")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntakeError(f"cannot read corpus manifest {path}: {exc}") from exc
    if payload.get("schema_version") != "r2b.corpus-manifest.v1":
        raise IntakeError("unsupported corpus manifest schema")
    allowed_hosts = {str(host).lower() for host in payload.get("allowed_hosts", [])}
    if not allowed_hosts:
        raise IntakeError("manifest must declare allowed_hosts")
    seen: set[str] = set()
    for dataset in payload.get("datasets", []):
        dataset_id = _safe_id(dataset.get("id"))
        if dataset_id in seen:
            raise IntakeError(f"duplicate dataset id: {dataset_id}")
        seen.add(dataset_id)
        _validate_url(str(dataset.get("url") or ""), allowed_hosts)
        max_bytes = int(dataset.get("max_bytes") or 0)
        if max_bytes <= 0:
            raise IntakeError(f"{dataset_id}: max_bytes must be positive")
        kind = dataset.get("kind")
        if kind == "https":
            _safe_filename(dataset.get("filename"))
            digest = str(dataset.get("sha256") or "")
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise IntakeError(f"{dataset_id}: invalid SHA-256")
        elif kind == "git":
            commit = str(dataset.get("commit") or "")
            if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
                raise IntakeError(f"{dataset_id}: invalid git commit")
            for item in dataset.get("sparse_paths", []):
                path_item = Path(str(item))
                if path_item.is_absolute() or ".." in path_item.parts:
                    raise IntakeError(f"{dataset_id}: unsafe sparse path {item!r}")
        else:
            raise IntakeError(f"{dataset_id}: unsupported kind {kind!r}")
    return payload


class _RedirectGuard(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        self.allowed_hosts = allowed_hosts
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        _validate_url(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(dataset: dict[str, Any], output: Path, allowed_hosts: set[str]) -> Path:
    destination = output / _safe_filename(dataset["filename"])
    expected = str(dataset["sha256"])
    if destination.is_file():
        actual = _sha256(destination)
        if actual == expected:
            print(f"verified {dataset['id']}: {destination}")
            return destination
        raise IntakeError(f"existing file has wrong SHA-256: {destination}")

    part = destination.with_suffix(destination.suffix + ".part")
    if part.exists():
        raise IntakeError(f"partial download already exists; inspect or remove it: {part}")
    request = urllib.request.Request(
        str(dataset["url"]),
        headers={"User-Agent": "r2b-corpus-intake/1"},
    )
    opener = urllib.request.build_opener(_RedirectGuard(allowed_hosts))
    maximum = int(dataset["max_bytes"])
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(request, timeout=60) as response, part.open("xb") as handle:
            _validate_url(response.geturl(), allowed_hosts)
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > maximum:
                raise IntakeError(
                    f"{dataset['id']}: server declared {declared} bytes, cap is {maximum}"
                )
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise IntakeError(f"{dataset['id']}: download exceeded {maximum} bytes")
                digest.update(chunk)
                handle.write(chunk)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise IntakeError(f"{dataset['id']}: download failed: {exc}") from exc
    actual = digest.hexdigest()
    if actual != expected:
        raise IntakeError(f"{dataset['id']}: SHA-256 mismatch: expected {expected}, got {actual}")
    part.replace(destination)
    print(f"fetched {dataset['id']}: {destination} ({total} bytes)")
    return destination


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "GIT_ASKPASS": "true",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def _git(args: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "http.followRedirects=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            *args,
        ],
        cwd=cwd,
        env=_git_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise IntakeError(f"git failed: {detail[-2000:]}")
    return completed.stdout.strip()


def _tree_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _fetch_git(dataset: dict[str, Any], output: Path) -> Path:
    destination = output / _safe_id(dataset["id"])
    expected = str(dataset["commit"])
    paths = [str(item) for item in dataset.get("sparse_paths", [])]
    if destination.exists():
        if not (destination / ".git").is_dir():
            raise IntakeError(f"existing path is not a git checkout: {destination}")
        actual = _git(["rev-parse", "HEAD"], cwd=destination)
        if actual != expected:
            raise IntakeError(f"{destination} is at {actual}, expected {expected}")
        if paths:
            _git(["sparse-checkout", "set", *paths], cwd=destination)
            _git(["checkout", "--quiet", expected], cwd=destination)
        print(f"verified {dataset['id']}: {destination} @ {actual}")
        return destination

    staging = output / f".{dataset['id']}.part"
    if staging.exists():
        raise IntakeError(f"partial git checkout already exists; inspect or remove it: {staging}")
    staging.mkdir()
    _git(["init", "--quiet", str(staging)])
    _git(["remote", "add", "origin", str(dataset["url"])], cwd=staging)
    _git(
        ["fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", expected],
        cwd=staging,
    )
    if paths:
        _git(["sparse-checkout", "init", "--cone"], cwd=staging)
        _git(["sparse-checkout", "set", *paths], cwd=staging)
    _git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=staging)
    actual = _git(["rev-parse", "HEAD"], cwd=staging)
    if actual != expected:
        raise IntakeError(f"checked out {actual}, expected {expected}")
    size = _tree_size(staging)
    if size > int(dataset["max_bytes"]):
        raise IntakeError(f"{dataset['id']}: checkout is {size} bytes, above its cap")
    staging.replace(destination)
    print(f"fetched {dataset['id']}: {destination} @ {actual} ({size} bytes)")
    return destination


def _selected(payload: dict[str, Any], names: list[str], all_datasets: bool) -> list[dict[str, Any]]:
    datasets = list(payload.get("datasets", []))
    by_id = {str(item["id"]): item for item in datasets}
    if all_datasets:
        return datasets
    if not names:
        raise IntakeError("name at least one dataset, or pass --all")
    unknown = [name for name in names if name not in by_id]
    if unknown:
        raise IntakeError(f"unknown dataset id(s): {', '.join(unknown)}")
    return [by_id[name] for name in names]


def _verify(dataset: dict[str, Any], output: Path) -> None:
    if dataset["kind"] == "https":
        path = output / _safe_filename(dataset["filename"])
        if not path.is_file():
            raise IntakeError(f"missing dataset file: {path}")
        actual = _sha256(path)
        if actual != dataset["sha256"]:
            raise IntakeError(f"{dataset['id']}: SHA-256 mismatch: {actual}")
        print(f"verified {dataset['id']}: {path}")
        return
    path = output / _safe_id(dataset["id"])
    if not (path / ".git").is_dir():
        raise IntakeError(f"missing git checkout: {path}")
    actual = _git(["rev-parse", "HEAD"], cwd=path)
    if actual != dataset["commit"]:
        raise IntakeError(f"{dataset['id']}: commit mismatch: {actual}")
    missing = [item for item in dataset.get("sparse_paths", []) if not (path / item).exists()]
    if missing:
        raise IntakeError(
            f"{dataset['id']}: missing sparse path(s): {', '.join(missing)}; rerun fetch"
        )
    print(f"verified {dataset['id']}: {path} @ {actual}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="validate and list pinned inputs; no network access")
    for command in ("fetch", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("datasets", nargs="*")
        child.add_argument("--all", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = load_manifest(args.manifest.resolve())
        if args.command == "list":
            for item in payload["datasets"]:
                identity = item.get("sha256") or item.get("commit")
                print(f"{item['id']:<38} {item['kind']:<5} {identity}")
            return 0
        output = args.output.expanduser().resolve()
        output.mkdir(parents=True, exist_ok=True)
        datasets = _selected(payload, args.datasets, args.all)
        allowed_hosts = {str(host).lower() for host in payload["allowed_hosts"]}
        for dataset in datasets:
            if args.command == "verify":
                _verify(dataset, output)
            elif dataset["kind"] == "https":
                _download(dataset, output, allowed_hosts)
            else:
                _fetch_git(dataset, output)
        return 0
    except IntakeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
