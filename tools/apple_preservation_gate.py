#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guard Apple source semantics, tests, fixtures, and symbols."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, Optional, Sequence


def strip_c_comments(text: str) -> str:
    out: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out.append(" ")
                index += 2
                state = "line"
                continue
            if char == "/" and nxt == "*":
                out.append(" ")
                index += 2
                state = "block"
                continue
            out.append(char)
            if char in ("\"", "'"):
                quote = char
                state = "quoted"
            index += 1
            continue
        if state == "line":
            if char in ("\n", "\r"):
                out.append(char)
                state = "code"
            index += 1
            continue
        if state == "block":
            if char == "*" and nxt == "/":
                out.extend((" ", " "))
                index += 2
                state = "code"
                continue
            if char in ("\n", "\r"):
                out.append(char)
            index += 1
            continue
        out.append(char)
        if char == "\\" and index + 1 < len(text):
            out.append(text[index + 1])
            index += 2
            continue
        if char == quote:
            state = "code"
        index += 1
    if state == "block":
        raise ValueError("unterminated C block comment")
    return "".join(out)


_TOKEN = re.compile(
    r'''(?:u8|u|U|L)?"(?:\\.|[^"\\])*"'''
    r'''|(?:u|U|L)?'(?:\\.|[^'\\])*' '''
    r'''|[A-Za-z_][A-Za-z0-9_]*'''
    r'''|(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)'''
    r'''(?:[eEpP][+-]?[0-9]+)?)[A-Za-z0-9_]*'''
    r'''|>>=|<<=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\|'''
    r'''|\*=|/=|%=|\+=|-=|&=|\^=|\|=|\#\#|[^\s]''',
    re.VERBOSE | re.DOTALL,
)


def _c_semantic_tokens(text: str) -> list[str]:
    # C translation phase 2 removes each backslash-newline pair before
    # comments are recognized. Preserve that ordering so a continued //
    # comment cannot hide a declaration from the semantic digest.
    spliced = re.sub(r"\\(?:\r\n|\n|\r)", "", text)
    stripped = strip_c_comments(spliced)
    tokens: list[str] = []
    for physical_line in stripped.splitlines(keepends=True):
        has_newline = physical_line.endswith(("\n", "\r"))
        content = physical_line.rstrip("\r\n") if has_newline else physical_line
        if re.match(r"^[ \t\f\v]*#", content):
            # Horizontal whitespace can change preprocessing semantics. Hash
            # the complete canonicalized directive rather than only tokens.
            tokens.extend(("<PP_LINE>", content))
            if has_newline:
                tokens.append("<PP_EOL>")
        else:
            tokens.extend(_TOKEN.findall(content))
    return tokens


def c_semantic_digest(data: bytes) -> str:
    tokens = _c_semantic_tokens(data.decode("utf-8"))
    digest = hashlib.sha256()
    for token in tokens:
        encoded = token.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def protected_semantic_errors(root: Path, expected: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for relative, wanted in sorted(expected.items()):
        path = root / relative
        if not path.is_file():
            errors.append(f"missing protected file: {relative}")
            continue
        try:
            actual = c_semantic_digest(path.read_bytes())
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            errors.append(f"cannot inspect protected file {relative}: {exc}")
            continue
        if actual != wanted:
            errors.append(f"semantic source change: {relative}")
    return errors


_TEST = re.compile(
    r"\bRFB_TEST\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.MULTILINE,
)


def test_inventory(root: Path, paths: Iterable[str]) -> list[str]:
    inventory: list[str] = []
    for relative in paths:
        path = root / relative
        text = strip_c_comments(path.read_text(encoding="utf-8"))
        inventory.extend(f"{suite}::{name}" for suite, name in _TEST.findall(text))
    return sorted(inventory)


def inventory_digest(inventory: Iterable[str]) -> str:
    data = "\n".join(sorted(inventory)).encode("utf-8") + b"\n"
    return hashlib.sha256(data).hexdigest()


def runner_test_inventory(
    root: Path, paths: Iterable[str], *, rdp_enabled: bool,
) -> list[str]:
    compiled_paths = [
        relative for relative in paths
        if rdp_enabled or not relative.startswith("tests/unit/rdp/")
    ]
    return test_inventory(root, compiled_paths)


def fixture_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise ValueError(f"fixture root has no files: {root}")
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def parse_nm_output(output: str) -> set[str]:
    symbols: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.endswith(":"):
            continue
        symbol = line.split()[-1]
        if symbol.startswith("_"):
            symbol = symbol[1:]
        symbols.add(symbol)
    return symbols


def binary_symbols(binary: Path) -> set[str]:
    commands = (
        ["nm", "-gjU", str(binary)],
        ["nm", "-g", "--defined-only", str(binary)],
        ["nm", "-g", str(binary)],
    )
    errors: list[str] = []
    for command in commands:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            return parse_nm_output(result.stdout)
        errors.append(result.stderr.strip())
    raise RuntimeError("nm failed: " + "; ".join(error for error in errors if error))


def _git_blob(root: Path, revision: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{path}"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"cannot read baseline {path}: {detail}")
    return result.stdout


def load_manifest(path: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 3:
        raise ValueError("unsupported Apple preservation manifest schema")
    for key in ("semantic_boundary", "protected_sources",
                "focused_test_sources", "fixture_roots",
                "protected_semantics_sha256", "required_symbols_file",
                "test_inventory_count", "test_inventory_sha256"):
        if key not in raw:
            raise ValueError(f"manifest missing {key}")
    if not isinstance(raw["semantic_boundary"], str) or not raw["semantic_boundary"]:
        raise ValueError("manifest semantic boundary must be documented")
    protected = set(raw["protected_sources"])
    protected.update(raw["focused_test_sources"])
    semantics = raw["protected_semantics_sha256"]
    if not isinstance(semantics, dict) or set(semantics) != protected:
        raise ValueError("protected semantic inventory does not match protected paths")
    if not all(
        isinstance(relative, str) and relative and
        isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
        for relative, digest in semantics.items()
    ):
        raise ValueError("invalid protected semantic digest")

    baseline = raw.get("prior_baseline")
    if not isinstance(baseline, dict):
        raise ValueError("manifest missing prior_baseline")
    for key in (
        "id", "approval", "test_inventory_count", "test_inventory_sha256",
        "added_protected_sources", "added_focused_test_sources",
        "changed_semantics_sha256",
    ):
        if key not in baseline:
            raise ValueError(f"prior baseline missing {key}")
    if not isinstance(baseline["id"], str) or not baseline["id"]:
        raise ValueError("prior baseline id must be documented")
    if not isinstance(baseline["approval"], str) or not baseline["approval"]:
        raise ValueError("prior baseline approval must be documented")
    prior_semantics = baseline["changed_semantics_sha256"]
    added_sources = set(baseline["added_protected_sources"])
    added_tests = set(baseline["added_focused_test_sources"])
    if not added_sources <= set(raw["protected_sources"]):
        raise ValueError("added protected source is absent from current boundary")
    if not added_tests <= set(raw["focused_test_sources"]):
        raise ValueError("added focused test is absent from current boundary")
    if not isinstance(prior_semantics, dict):
        raise ValueError("invalid prior semantic inventory")
    for relative, digest in prior_semantics.items():
        if relative not in semantics or relative in added_sources:
            raise ValueError("prior semantic path is not a changed existing path")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid prior semantic digest")
        if digest == semantics[relative]:
            raise ValueError("prior semantic digest does not describe a change")
    if not isinstance(baseline["test_inventory_count"], int):
        raise ValueError("invalid prior test inventory count")
    if not re.fullmatch(r"[0-9a-f]{64}", baseline["test_inventory_sha256"]):
        raise ValueError("invalid prior test inventory digest")
    return raw


def _required_symbols(root: Path, relative: str) -> set[str]:
    result: set[str] = set()
    for raw in (root / relative).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            result.add(line)
    if not result:
        raise ValueError("required symbol inventory is empty")
    return result


def verify(root: Path, manifest: dict, *, baseline_ref: Optional[str] = None,
           binary: Optional[Path] = None,
           test_runner: Optional[Path] = None,
           run_focused: bool = False,
           rdp_enabled: bool = True) -> list[str]:
    errors: list[str] = []
    source_paths = list(manifest["protected_sources"])
    test_paths = list(manifest["focused_test_sources"])
    errors.extend(protected_semantic_errors(
        root, manifest["protected_semantics_sha256"]
    ))
    if baseline_ref is not None:
        for relative in source_paths + test_paths:
            path = root / relative
            if not path.is_file():
                continue
            try:
                baseline = _git_blob(root, baseline_ref, relative)
                if c_semantic_digest(path.read_bytes()) != c_semantic_digest(baseline):
                    errors.append(f"semantic source change: {relative}")
            except (OSError, RuntimeError, UnicodeDecodeError, ValueError) as exc:
                errors.append(str(exc))

    try:
        inventory = test_inventory(root, test_paths)
        if len(inventory) != manifest["test_inventory_count"]:
            errors.append(
                f"focused test count changed: {len(inventory)} != "
                f"{manifest['test_inventory_count']}"
            )
        if inventory_digest(inventory) != manifest["test_inventory_sha256"]:
            errors.append("focused test inventory changed")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        errors.append(f"cannot inspect focused tests: {exc}")
        inventory = []

    for relative, expected in manifest["fixture_roots"].items():
        try:
            actual = fixture_tree_digest(root / relative)
            if actual != expected:
                errors.append(f"functional fixture bytes changed: {relative}")
        except (OSError, ValueError) as exc:
            errors.append(str(exc))

    try:
        required = _required_symbols(root, manifest["required_symbols_file"])
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
        required = set()

    if binary is not None:
        try:
            missing = sorted(required - binary_symbols(binary))
            if missing:
                errors.append("release binary is missing symbols: " + ", ".join(missing))
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc))

    if test_runner is not None:
        runner_inventory = runner_test_inventory(
            root, test_paths, rdp_enabled=rdp_enabled
        )
        result = subprocess.run(
            [str(test_runner), "--list"], check=False, capture_output=True, text=True,
            timeout=60,
        )
        if result.returncode != 0:
            errors.append(f"test runner --list failed with status {result.returncode}")
        else:
            listed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            missing_tests = sorted(set(runner_inventory) - listed)
            if missing_tests:
                errors.append("test runner is missing focused tests: " +
                              ", ".join(missing_tests))
        if run_focused and not errors:
            suites = sorted({
                item.split("::", 1)[0] for item in runner_inventory
            })
            for suite in suites:
                result = subprocess.run(
                    [str(test_runner), "--filter", suite],
                    check=False,
                    timeout=300,
                )
                if result.returncode != 0:
                    errors.append(f"focused suite failed: {suite}")
    return errors


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Verify Apple behavior assets.")
    parser.add_argument("--root", type=Path, default=root_default)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--baseline-ref",
                        help="compare protected C semantics with this Git revision")
    parser.add_argument("--binary", type=Path,
                        help="product binary whose required symbols are checked")
    parser.add_argument("--test-runner", type=Path,
                        help="compiled test runner whose inventory is checked")
    parser.add_argument("--run-focused", action="store_true",
                        help="run every focused suite (requires --test-runner)")
    parser.add_argument("--without-rdp", action="store_true",
                        help="accept a runner compiled without RDP-only tests")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    manifest_path = args.manifest or root / "tools" / "apple_preservation_manifest.json"
    if args.run_focused and args.test_runner is None:
        print("Apple preservation gate error: --run-focused needs --test-runner",
              file=sys.stderr)
        return 2
    try:
        manifest = load_manifest(manifest_path)
        errors = verify(
            root,
            manifest,
            baseline_ref=args.baseline_ref,
            binary=args.binary,
            test_runner=args.test_runner,
            run_focused=args.run_focused,
            rdp_enabled=not args.without_rdp,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Apple preservation gate error: {exc}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"Apple preservation gate: {error}", file=sys.stderr)
    if errors:
        print(f"Apple preservation gate: FAIL ({len(errors)} error(s))", file=sys.stderr)
        return 1
    print("Apple preservation gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
