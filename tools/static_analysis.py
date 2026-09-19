#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, parallel, cached Clang static-analysis driver."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path


def digest_file(path: Path, hasher) -> None:
    hasher.update(path.as_posix().encode())
    hasher.update(path.read_bytes())


def analyze_one(source: Path, args, shared_digest: str, flags):
    rel = source.relative_to(args.root)
    output = args.output / rel
    output = output.with_suffix(output.suffix + ".log")
    cache = output.with_suffix(output.suffix + ".json")
    hasher = hashlib.sha256()
    digest_file(source, hasher)
    hasher.update(shared_digest.encode())
    hasher.update("\0".join([args.compiler, *flags]).encode())
    compiler_path = shutil.which(args.compiler)
    if compiler_path is not None:
        digest_file(Path(compiler_path).resolve(), hasher)
    key = hasher.hexdigest()
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached == {"key": key, "clean": True}:
            return rel.as_posix(), "cached", ""
    except (OSError, json.JSONDecodeError):
        pass
    command = [
        args.compiler,
        "--analyze",
        "-Xanalyzer",
        "-analyzer-output=text",
        str(source),
        *flags,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=args.timeout,
        )
        lines = [
            line for line in result.stdout.splitlines()
            if line.strip() and "unused-command-line-argument" not in line
        ]
        detail = "\n".join(lines)
        status = "clean"
        if result.returncode != 0:
            status = f"error ({result.returncode})"
        elif detail:
            status = "finding"
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        detail = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(detail + ("\n" if detail else ""), encoding="utf-8")
    if status == "clean":
        cache.write_text(json.dumps({"key": key, "clean": True}) + "\n")
    else:
        try:
            cache.unlink()
        except FileNotFoundError:
            pass
    return rel.as_posix(), status, detail


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    args.output = args.output.resolve()
    if args.jobs < 1 or args.timeout < 1:
        parser.error("--jobs and --timeout must be positive")
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        parser.error("invalid shard index/count")
    if args.files:
        sources = [
            (args.root / path).resolve() if not Path(path).is_absolute()
            else Path(path).resolve()
            for path in args.files
        ]
    else:
        sources = sorted((args.root / "src").rglob("*.c"))
    sources = [
        source for index, source in enumerate(sorted(sources))
        if index % args.shard_count == args.shard_index
    ]
    headers = sorted((args.root / "include").rglob("*.h"))
    headers += sorted((args.root / "src").rglob("*.h"))
    shared = hashlib.sha256()
    for header in headers:
        digest_file(header, shared)
    flags = shlex.split(os.environ.get("SA_CFLAGS", ""))
    args.output.mkdir(parents=True, exist_ok=True)
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(analyze_one, source, args, shared.hexdigest(), flags)
            for source in sources
        ]
        for future in concurrent.futures.as_completed(futures):
            rel, status, detail = future.result()
            if status not in {"clean", "cached"}:
                failures.append((rel, status, detail))
    for rel, status, detail in sorted(failures):
        print(f"{status.upper()} in {rel}:")
        if detail:
            print(detail)
    if failures:
        return 1
    print(
        f"ok: Clang static analyzer clean ({len(sources)} files, "
        f"shard {args.shard_index + 1}/{args.shard_count})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
