#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject public-tree residue while preserving product identifiers."""

from __future__ import annotations

import argparse
import base64
import bisect
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    pattern: Optional[re.Pattern[str]]
    token_hashes: tuple["TokenHash", ...] = ()
    text_only: bool = False


@dataclass(frozen=True)
class TokenHash:
    token_count: int
    digest: bytes
    prefix_length: int = 0
    remainder: Optional[re.Pattern[str]] = None
    next_tokens: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True, order=True)
class Finding:
    location: str
    category: str
    rule_id: str


def load_manifest(path: Path) -> tuple[list[Rule], tuple[str, ...]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") not in {1, 2}:
        raise ValueError("unsupported vocabulary manifest schema")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    seen_categories: set[str] = set()
    for item in raw.get("rules", []):
        rule_id = item.get("id")
        category = item.get("category")
        encoded = item.get("regex_b64")
        expression = item.get("regex")
        if not all(isinstance(value, str) and value for value in
                   (rule_id, category)):
            raise ValueError("each vocabulary rule needs an id and category")
        if rule_id in seen_ids:
            raise ValueError(f"duplicate vocabulary rule id: {rule_id}")
        seen_ids.add(rule_id)
        seen_categories.add(category)
        if encoded is not None:
            if not isinstance(encoded, str) or not encoded:
                raise ValueError(f"invalid encoded expression for {rule_id}")
            try:
                expression = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"invalid encoded expression for {rule_id}") from exc
        elif expression is not None and not isinstance(expression, str):
            raise ValueError(f"invalid structural expression for {rule_id}")
        flags = re.ASCII
        if item.get("ignore_case", False):
            flags |= re.IGNORECASE
        pattern = re.compile(expression, flags) if expression else None
        text_only = item.get("text_only", False)
        if not isinstance(text_only, bool):
            raise ValueError(f"invalid text-only scope for {rule_id}")

        token_hashes: list[TokenHash] = []
        for literal in item.get("token_sha256", []):
            if not isinstance(literal, dict):
                raise ValueError(f"invalid token digest for {rule_id}")
            token_count = literal.get("token_count")
            digest_text = literal.get("digest")
            if (not isinstance(token_count, int) or token_count < 1 or
                    not isinstance(digest_text, str) or
                    not re.fullmatch(r"[0-9a-f]{64}", digest_text)):
                raise ValueError(f"invalid token digest for {rule_id}")
            prefix_length = literal.get("prefix_length", 0)
            if not isinstance(prefix_length, int) or prefix_length < 0:
                raise ValueError(f"invalid token prefix length for {rule_id}")
            remainder_text = literal.get("remainder_regex")
            if remainder_text is not None and not isinstance(remainder_text, str):
                raise ValueError(f"invalid token remainder for {rule_id}")
            remainder = (re.compile(remainder_text, re.ASCII | re.IGNORECASE)
                         if remainder_text is not None else None)
            next_texts = literal.get("next_token_regex", [])
            if (not isinstance(next_texts, list) or
                    not all(isinstance(value, str) for value in next_texts)):
                raise ValueError(f"invalid following-token rule for {rule_id}")
            next_tokens = tuple(
                re.compile(value, re.ASCII | re.IGNORECASE) for value in next_texts
            )
            if prefix_length and token_count != 1:
                raise ValueError(f"token prefixes require one token for {rule_id}")
            token_hashes.append(TokenHash(
                token_count,
                bytes.fromhex(digest_text),
                prefix_length,
                remainder,
                next_tokens,
            ))
        if pattern is None and not token_hashes:
            raise ValueError(f"rule {rule_id} has no matcher")
        rules.append(Rule(
            rule_id, category, pattern, tuple(token_hashes), text_only
        ))

    if not rules or not seen_categories:
        raise ValueError("the manifest needs at least one vocabulary category")

    retained = tuple(raw.get("retained_identifiers", ()))
    if not retained or not all(isinstance(value, str) and value for value in retained):
        raise ValueError("retained_identifiers must be a non-empty string list")
    for identifier in retained:
        for rule in rules:
            if scan_blob(identifier.encode(), "retained", [rule]):
                raise ValueError(
                    f"retained product identifier conflicts with {rule.rule_id}"
                )
    return rules, retained


def _location(label: str, newlines: Sequence[int], start: int,
              binary: bool) -> str:
    if binary:
        return f"{label}:byte:{start}"
    line = bisect.bisect_left(newlines, start) + 1
    prior = newlines[line - 2] if line > 1 else -1
    return f"{label}:{line}:{start - prior}"


def _hashed_match_offsets(
    text: str, rules: Sequence[Rule]
) -> dict[tuple[int, int], list[int]]:
    """Return token-digest matches keyed by rule and item position.

    Tokenization and each distinct hash-window calculation happen once per
    blob.  The digest indexes share that work across every rule which uses the
    same token count or prefix length.
    """
    indexed: list[tuple[int, int, TokenHash]] = [
        (rule_index, item_index, item)
        for rule_index, rule in enumerate(rules)
        for item_index, item in enumerate(rule.token_hashes)
    ]
    if not indexed:
        return {}

    tokens = list(re.finditer(r"[A-Za-z0-9]+", text, re.ASCII))
    normalized = [match.group(0).lower() for match in tokens]
    matches: dict[tuple[int, int], list[int]] = {}

    # Source and history often repeat identifiers. Cache a bounded set of
    # token windows so repeated text does not require another SHA-256 call.
    # The bound keeps unique or hostile input from growing memory without
    # limit, and the digest remains the exact manifest contract.
    @lru_cache(maxsize=4096)
    def window_digest(words: tuple[str, ...]) -> bytes:
        return hashlib.sha256(" ".join(words).encode("ascii")).digest()

    @lru_cache(maxsize=4096)
    def prefix_digest(value: str) -> bytes:
        return hashlib.sha256(value.encode("ascii")).digest()

    windows: dict[int, dict[bytes, list[tuple[int, int, TokenHash]]]] = {}
    prefixes: dict[int, dict[bytes, list[tuple[int, int, TokenHash]]]] = {}
    for entry in indexed:
        item = entry[2]
        groups = prefixes if item.prefix_length else windows
        width = item.prefix_length if item.prefix_length else item.token_count
        groups.setdefault(width, {}).setdefault(item.digest, []).append(entry)

    for token_count, digest_index in windows.items():
        for start in range(0, len(tokens) - token_count + 1):
            digest = window_digest(tuple(
                normalized[start:start + token_count]
            ))
            for rule_index, item_index, item in digest_index.get(digest, ()):
                needed = item.token_count + len(item.next_tokens)
                if start + needed > len(tokens):
                    continue
                following = normalized[
                    start + item.token_count:start + needed
                ]
                if any(pattern.fullmatch(value) is None
                       for pattern, value in zip(item.next_tokens, following)):
                    continue
                matches.setdefault((rule_index, item_index), []).append(
                    tokens[start].start()
                )

    for prefix_length, digest_index in prefixes.items():
        for start, token in enumerate(normalized):
            if len(token) <= prefix_length:
                continue
            digest = prefix_digest(token[:prefix_length])
            for rule_index, item_index, item in digest_index.get(digest, ()):
                remainder_text = token[prefix_length:]
                if (item.remainder is None or
                        item.remainder.fullmatch(remainder_text) is None):
                    continue
                needed = 1 + len(item.next_tokens)
                if start + needed > len(tokens):
                    continue
                following = normalized[start + 1:start + needed]
                if any(pattern.fullmatch(value) is None
                       for pattern, value in zip(item.next_tokens, following)):
                    continue
                matches.setdefault((rule_index, item_index), []).append(
                    tokens[start].start()
                )
    return matches


def is_textual_blob(data: bytes) -> bool:
    """Return true for valid UTF-8 without NUL or non-whitespace controls."""
    if b"\0" in data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(char.isprintable() or char.isspace() for char in text)


def scan_blob(data: bytes, label: str, rules: Sequence[Rule], *,
              binary: bool = False) -> list[Finding]:
    textual = is_textual_blob(data)
    active_rules = [
        rule for rule in rules if not rule.text_only or textual
    ]
    text = data.decode("latin-1")
    newlines = [index for index, char in enumerate(text) if char == "\n"]
    hashed_offsets = _hashed_match_offsets(text, active_rules)
    findings: list[Finding] = []
    for rule_index, rule in enumerate(active_rules):
        if rule.pattern is not None:
            for match in rule.pattern.finditer(text):
                findings.append(Finding(
                    _location(label, newlines, match.start(), binary),
                    rule.category,
                    rule.rule_id,
                ))
        for item_index, _item in enumerate(rule.token_hashes):
            for start in hashed_offsets.get((rule_index, item_index), ()):
                findings.append(Finding(
                    _location(label, newlines, start, binary),
                    rule.category,
                    rule.rule_id,
                ))
    return findings


def _require_file_range(data: bytes, offset: int, size: int,
                        description: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"invalid {description} range in release binary")


def _unpack_binary(format_text: str, data: bytes, offset: int,
                   description: str) -> tuple[object, ...]:
    size = struct.calcsize(format_text)
    _require_file_range(data, offset, size, description)
    return struct.unpack_from(format_text, data, offset)


def _macho_non_string_section_ranges(
        data: bytes) -> Optional[list[tuple[int, int]]]:
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    fat_format = fat_formats.get(data[:4])
    if fat_format is not None:
        endian, is_64_fat = fat_format
        _magic, slice_count = _unpack_binary(
            endian + "II", data, 0, "universal Mach-O header"
        )
        slice_count = int(slice_count)
        entry_format = endian + ("iiQQII" if is_64_fat else "iiIII")
        entry_size = struct.calcsize(entry_format)
        table_size = slice_count * entry_size
        _require_file_range(data, 8, table_size,
                            "universal Mach-O architecture table")
        table_end = 8 + table_size
        slices: list[tuple[int, int]] = []
        for index in range(slice_count):
            entry = _unpack_binary(
                entry_format, data, 8 + index * entry_size,
                "universal Mach-O architecture",
            )
            slice_offset = int(entry[2])
            slice_size = int(entry[3])
            _require_file_range(data, slice_offset, slice_size,
                                "universal Mach-O slice")
            if slice_offset < table_end:
                raise ValueError("universal Mach-O slice overlaps its header")
            slices.append((slice_offset, slice_offset + slice_size))
        ordered = sorted(slices)
        for prior, current in zip(ordered, ordered[1:]):
            if prior[1] > current[0]:
                raise ValueError("overlapping universal Mach-O slices")
        ranges: list[tuple[int, int]] = []
        for slice_offset, slice_end in slices:
            nested = _macho_non_string_section_ranges(
                data[slice_offset:slice_end]
            )
            if nested is None:
                raise ValueError("unrecognized universal Mach-O slice")
            ranges.extend((slice_offset + start, slice_offset + end)
                          for start, end in nested)
        return ranges

    formats = {
        b"\xcf\xfa\xed\xfe": ("<", True),
        b"\xfe\xed\xfa\xcf": (">", True),
        b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xce": (">", False),
    }
    binary_format = formats.get(data[:4])
    if binary_format is None:
        return None
    endian, is_64 = binary_format
    header_format = endian + ("IiiIIIII" if is_64 else "IiiIIII")
    header = _unpack_binary(header_format, data, 0, "Mach-O header")
    command_count = int(header[4])
    command_bytes = int(header[5])
    command_offset = struct.calcsize(header_format)
    _require_file_range(data, command_offset, command_bytes,
                        "Mach-O load-command")
    command_end = command_offset + command_bytes
    ranges: list[tuple[int, int]] = []
    segment_command = 0x19 if is_64 else 0x1
    segment_size = 72 if is_64 else 56
    section_size = 80 if is_64 else 68
    segment_format = endian + (
        "II16sQQQQiiII" if is_64 else "II16sIIIIiiII"
    )
    section_format = endian + (
        "16s16sQQIIIIIIII" if is_64 else "16s16sIIIIIIIII"
    )
    instruction_flags = 0x80000000 | 0x00000400

    for _index in range(command_count):
        command, size = _unpack_binary(
            endian + "II", data, command_offset, "Mach-O load-command"
        )
        command = int(command)
        size = int(size)
        if size < 8 or size > command_end - command_offset:
            raise ValueError("invalid Mach-O load-command size")
        if command == segment_command:
            if size < segment_size:
                raise ValueError("short Mach-O segment command")
            segment = _unpack_binary(
                segment_format, data, command_offset, "Mach-O segment"
            )
            segment_name = bytes(segment[2])
            virtual_address = int(segment[3])
            virtual_size = int(segment[4])
            file_offset = int(segment[5])
            file_size = int(segment[6])
            initial_protection = int(segment[8])
            section_count = int(segment[9])
            _require_file_range(data, file_offset, file_size,
                                "Mach-O segment")
            section_bytes = section_count * section_size
            if section_bytes > size - segment_size:
                raise ValueError("invalid Mach-O section count")
            section_offset = command_offset + segment_size
            for _section_index in range(section_count):
                section = _unpack_binary(
                    section_format, data, section_offset, "Mach-O section"
                )
                section_file_offset = int(section[4])
                section_file_size = int(section[3])
                section_flags = int(section[8])
                section_segment_name = bytes(section[1])
                section_address = int(section[2])
                section_type = section_flags & 0xff
                if ((section_flags & instruction_flags) != 0 and
                        section_type in {0x1, 0x0c, 0x12}):
                    raise ValueError(
                        "non-file-backed Mach-O instruction section"
                    )
                if section_type not in {0x1, 0x0c, 0x12, 0x2}:
                    if ((section_flags & instruction_flags) != 0 and
                            (initial_protection & 0x4) == 0):
                        raise ValueError(
                            "Mach-O instruction section is not executable"
                        )
                    if section_segment_name != segment_name:
                        raise ValueError(
                            "Mach-O section has wrong segment name"
                        )
                    _require_file_range(
                        data, section_file_offset, section_file_size,
                        "Mach-O section",
                    )
                    relative_offset = section_file_offset - file_offset
                    if (relative_offset < 0 or relative_offset > file_size or
                            section_file_size > file_size - relative_offset):
                        raise ValueError(
                            "Mach-O section is outside its segment"
                        )
                    relative_address = section_address - virtual_address
                    if (relative_address < 0 or
                            relative_address > virtual_size or
                            section_file_size >
                            virtual_size - relative_address):
                        raise ValueError(
                            "Mach-O section has invalid address"
                        )
                    if relative_address != relative_offset:
                        raise ValueError(
                            "Mach-O section mapping is inconsistent"
                        )
                    ranges.append((section_file_offset,
                                   section_file_offset + section_file_size))
                section_offset += section_size
        command_offset += size
    if command_offset != command_end:
        raise ValueError("Mach-O load-command size mismatch")
    return ranges


def _macho_symbol_record_ranges(
        data: bytes) -> Optional[list[tuple[int, int]]]:
    """Locate fixed-width nlist records, excluding their string tables."""
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    fat_format = fat_formats.get(data[:4])
    if fat_format is not None:
        endian, is_64_fat = fat_format
        _magic, slice_count = _unpack_binary(
            endian + "II", data, 0, "universal Mach-O header"
        )
        slice_count = int(slice_count)
        entry_format = endian + ("iiQQII" if is_64_fat else "iiIII")
        entry_size = struct.calcsize(entry_format)
        _require_file_range(
            data, 8, slice_count * entry_size,
            "universal Mach-O architecture table",
        )
        ranges: list[tuple[int, int]] = []
        for index in range(slice_count):
            entry = _unpack_binary(
                entry_format, data, 8 + index * entry_size,
                "universal Mach-O architecture",
            )
            slice_offset = int(entry[2])
            slice_size = int(entry[3])
            _require_file_range(
                data, slice_offset, slice_size, "universal Mach-O slice"
            )
            nested = _macho_symbol_record_ranges(
                data[slice_offset:slice_offset + slice_size]
            )
            if nested is None:
                raise ValueError("unrecognized universal Mach-O slice")
            ranges.extend(
                (slice_offset + start, slice_offset + end)
                for start, end in nested
            )
        return ranges

    formats = {
        b"\xcf\xfa\xed\xfe": ("<", True),
        b"\xfe\xed\xfa\xcf": (">", True),
        b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xce": (">", False),
    }
    binary_format = formats.get(data[:4])
    if binary_format is None:
        return None
    endian, is_64 = binary_format
    header_format = endian + ("IiiIIIII" if is_64 else "IiiIIII")
    header = _unpack_binary(header_format, data, 0, "Mach-O header")
    command_count = int(header[4])
    command_bytes = int(header[5])
    command_offset = struct.calcsize(header_format)
    _require_file_range(
        data, command_offset, command_bytes, "Mach-O load-command"
    )
    command_end = command_offset + command_bytes
    record_size = 16 if is_64 else 12
    ranges: list[tuple[int, int]] = []
    for _index in range(command_count):
        command, size = _unpack_binary(
            endian + "II", data, command_offset, "Mach-O load-command"
        )
        command = int(command)
        size = int(size)
        if size < 8 or size > command_end - command_offset:
            raise ValueError("invalid Mach-O load-command size")
        if command == 0x2:
            if size < 24:
                raise ValueError("short Mach-O symbol-table command")
            _cmd, _size, symbol_offset, symbol_count, string_offset, string_size = (
                _unpack_binary(
                    endian + "IIIIII", data, command_offset,
                    "Mach-O symbol-table command",
                )
            )
            symbol_offset = int(symbol_offset)
            symbol_bytes = int(symbol_count) * record_size
            string_offset = int(string_offset)
            string_size = int(string_size)
            _require_file_range(
                data, symbol_offset, symbol_bytes, "Mach-O symbol records"
            )
            _require_file_range(
                data, string_offset, string_size, "Mach-O symbol strings"
            )
            symbol_end = symbol_offset + symbol_bytes
            string_end = string_offset + string_size
            if symbol_bytes > 0 and string_size > 0 and not (
                    symbol_end <= string_offset or string_end <= symbol_offset):
                raise ValueError("Mach-O symbol records overlap symbol strings")
            if symbol_bytes > 0:
                ranges.append((symbol_offset, symbol_end))
        command_offset += size
    if command_offset != command_end:
        raise ValueError("Mach-O load-command size mismatch")
    return ranges


def _macho_code_signature_ranges(
        data: bytes) -> Optional[list[tuple[int, int]]]:
    """Locate opaque Mach-O code-signature blobs."""
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    fat_format = fat_formats.get(data[:4])
    if fat_format is not None:
        endian, is_64_fat = fat_format
        _magic, slice_count = _unpack_binary(
            endian + "II", data, 0, "universal Mach-O header"
        )
        slice_count = int(slice_count)
        entry_format = endian + ("iiQQII" if is_64_fat else "iiIII")
        entry_size = struct.calcsize(entry_format)
        _require_file_range(
            data, 8, slice_count * entry_size,
            "universal Mach-O architecture table",
        )
        ranges: list[tuple[int, int]] = []
        for index in range(slice_count):
            entry = _unpack_binary(
                entry_format, data, 8 + index * entry_size,
                "universal Mach-O architecture",
            )
            slice_offset = int(entry[2])
            slice_size = int(entry[3])
            _require_file_range(
                data, slice_offset, slice_size, "universal Mach-O slice"
            )
            nested = _macho_code_signature_ranges(
                data[slice_offset:slice_offset + slice_size]
            )
            if nested is None:
                raise ValueError("unrecognized universal Mach-O slice")
            ranges.extend(
                (slice_offset + start, slice_offset + end)
                for start, end in nested
            )
        return ranges

    formats = {
        b"\xcf\xfa\xed\xfe": ("<", True),
        b"\xfe\xed\xfa\xcf": (">", True),
        b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xce": (">", False),
    }
    binary_format = formats.get(data[:4])
    if binary_format is None:
        return None
    endian, is_64 = binary_format
    header_format = endian + ("IiiIIIII" if is_64 else "IiiIIII")
    header = _unpack_binary(header_format, data, 0, "Mach-O header")
    command_count = int(header[4])
    command_bytes = int(header[5])
    command_offset = struct.calcsize(header_format)
    _require_file_range(
        data, command_offset, command_bytes, "Mach-O load-command"
    )
    command_end = command_offset + command_bytes
    ranges: list[tuple[int, int]] = []
    for _index in range(command_count):
        command, size = _unpack_binary(
            endian + "II", data, command_offset, "Mach-O load-command"
        )
        command = int(command)
        size = int(size)
        if size < 8 or size > command_end - command_offset:
            raise ValueError("invalid Mach-O load-command size")
        if command == 0x1D:
            if size < 16:
                raise ValueError("short Mach-O code-signature command")
            _cmd, _size, signature_offset, signature_size = _unpack_binary(
                endian + "IIII", data, command_offset,
                "Mach-O code-signature command",
            )
            signature_offset = int(signature_offset)
            signature_size = int(signature_size)
            _require_file_range(
                data, signature_offset, signature_size,
                "Mach-O code signature",
            )
            if signature_size > 0:
                ranges.append(
                    (signature_offset, signature_offset + signature_size)
                )
        command_offset += size
    if command_offset != command_end:
        raise ValueError("Mach-O load-command size mismatch")
    return ranges


def _elf_executable_ranges(data: bytes) -> Optional[list[tuple[int, int]]]:
    if data[:4] != b"\x7fELF":
        return None
    if len(data) < 16 or data[4] not in {1, 2} or data[5] not in {1, 2}:
        raise ValueError("unsupported ELF release binary")
    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    header_format = endian + (
        "16sHHIQQQIHHHHHH" if is_64 else "16sHHIIIIIHHHHHH"
    )
    header = _unpack_binary(header_format, data, 0, "ELF header")
    program_offset = int(header[5])
    section_offset = int(header[6])
    program_entry_size = int(header[9])
    program_count = int(header[10])
    section_entry_size = int(header[11])
    section_count = int(header[12])
    section_format = endian + (
        "IIQQQQIIQQ" if is_64 else "IIIIIIIIII"
    )
    section_min_size = struct.calcsize(section_format)
    first_section: Optional[tuple[object, ...]] = None
    if section_offset != 0:
        if section_entry_size < section_min_size:
            raise ValueError("short ELF section-header entry")
        first_section = _unpack_binary(
            section_format, data, section_offset, "ELF section header"
        )
        if section_count == 0:
            section_count = int(first_section[5])
    if program_count == 0xffff:
        if first_section is None:
            raise ValueError(
                "ELF extended program count needs section metadata"
            )
        program_count = int(first_section[7])
    ranges: list[tuple[int, int]] = []
    program_format = endian + (
        "IIQQQQQQ" if is_64 else "IIIIIIII"
    )
    program_min_size = struct.calcsize(program_format)
    executable_segments: list[tuple[int, int, int, int]] = []
    if program_count > 0:
        if program_offset == 0 or program_entry_size < program_min_size:
            raise ValueError("invalid ELF program-header table")
        _require_file_range(
            data, program_offset, program_count * program_entry_size,
            "ELF program-header table",
        )
        for index in range(program_count):
            program = _unpack_binary(
                program_format,
                data,
                program_offset + index * program_entry_size,
                "ELF program header",
            )
            if is_64:
                kind, flags = int(program[0]), int(program[1])
                file_offset, file_size = int(program[2]), int(program[5])
                virtual_address, memory_size = (
                    int(program[3]), int(program[6])
                )
            else:
                kind, flags = int(program[0]), int(program[6])
                file_offset, file_size = int(program[1]), int(program[4])
                virtual_address, memory_size = (
                    int(program[2]), int(program[5])
                )
            if kind == 1 and (flags & 0x1) != 0 and file_size > 0:
                _require_file_range(data, file_offset, file_size,
                                    "ELF executable segment")
                if memory_size < file_size:
                    raise ValueError(
                        "ELF executable segment has invalid memory size"
                    )
                executable_segments.append(
                    (file_offset, file_offset + file_size, virtual_address,
                     virtual_address + memory_size)
                )

    # A linked image without section metadata cannot distinguish instructions
    # from data inside an executable load segment. Scan it in full.
    if section_offset == 0:
        return None
    _require_file_range(
        data, section_offset, section_count * section_entry_size,
        "ELF section-header table",
    )
    for index in range(section_count):
        section = _unpack_binary(
            section_format, data,
            section_offset + index * section_entry_size,
            "ELF section header",
        )
        section_type = int(section[1])
        flags = int(section[2])
        virtual_address = int(section[3])
        file_offset = int(section[4])
        file_size = int(section[5])
        if (flags & 0x4) != 0:
            if (flags & 0x2) == 0:
                raise ValueError("ELF instruction section is not allocated")
            if section_type == 8:
                raise ValueError("non-file-backed ELF instruction section")
            if file_size == 0:
                continue
            _require_file_range(data, file_offset, file_size,
                                "ELF executable section")
            section_end = file_offset + file_size
            virtual_end = virtual_address + file_size
            if not any(
                file_start <= file_offset and section_end <= file_end and
                memory_start <= virtual_address and virtual_end <= memory_end and
                virtual_address - memory_start == file_offset - file_start
                for file_start, file_end, memory_start, memory_end
                in executable_segments
            ):
                raise ValueError(
                    "ELF instruction section has invalid segment mapping"
                )
            ranges.append((file_offset, section_end))
    return ranges


def _elf_opaque_metadata_ranges(
        data: bytes) -> Optional[list[tuple[int, int]]]:
    """Locate validated fixed-width ELF records, excluding string tables."""
    if data[:4] != b"\x7fELF":
        return None
    if len(data) < 16 or data[4] not in {1, 2} or data[5] not in {1, 2}:
        raise ValueError("unsupported ELF release binary")
    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    header_format = endian + (
        "16sHHIQQQIHHHHHH" if is_64 else "16sHHIIIIIHHHHHH"
    )
    header = _unpack_binary(header_format, data, 0, "ELF header")
    section_offset = int(header[6])
    section_entry_size = int(header[11])
    section_count = int(header[12])
    if section_offset == 0:
        return []

    section_format = endian + (
        "IIQQQQIIQQ" if is_64 else "IIIIIIIIII"
    )
    section_min_size = struct.calcsize(section_format)
    if section_entry_size < section_min_size:
        raise ValueError("short ELF section-header entry")
    first_section = _unpack_binary(
        section_format, data, section_offset, "ELF section header"
    )
    if section_count == 0:
        section_count = int(first_section[5])
    _require_file_range(
        data, section_offset, section_count * section_entry_size,
        "ELF section-header table",
    )
    sections = [
        _unpack_binary(
            section_format, data,
            section_offset + index * section_entry_size,
            "ELF section header",
        )
        for index in range(section_count)
    ]

    # These sections contain only fixed-width linker records. Names and other
    # human-readable values referenced by them live in SHT_STRTAB sections,
    # which deliberately remain searchable.
    entry_sizes = {
        2: 24 if is_64 else 16,       # SHT_SYMTAB
        4: 24 if is_64 else 12,       # SHT_RELA
        9: 16 if is_64 else 8,        # SHT_REL
        11: 24 if is_64 else 16,      # SHT_DYNSYM
        19: 8 if is_64 else 4,        # SHT_RELR
        0x6fffffff: 2,                # SHT_GNU_versym
    }
    ranges: list[tuple[int, int]] = []
    for section in sections:
        section_type = int(section[1])
        expected_entry_size = entry_sizes.get(section_type)
        if expected_entry_size is None:
            continue
        file_offset = int(section[4])
        file_size = int(section[5])
        link = int(section[6])
        entry_size = int(section[9])
        if entry_size != expected_entry_size:
            raise ValueError("invalid ELF metadata entry size")
        if file_size % entry_size != 0:
            raise ValueError("partial ELF metadata record")
        _require_file_range(data, file_offset, file_size,
                            "ELF metadata section")
        if section_type in {2, 11}:
            if link >= section_count or int(sections[link][1]) != 3:
                raise ValueError("ELF symbol table has invalid string table")
        elif section_type in {4, 9}:
            if link >= section_count or int(sections[link][1]) not in {2, 11}:
                raise ValueError("ELF relocation section has invalid symbols")
        elif section_type == 0x6fffffff:
            if link >= section_count or int(sections[link][1]) != 11:
                raise ValueError("ELF version section has invalid symbols")
        if file_size > 0:
            ranges.append((file_offset, file_offset + file_size))
    return ranges


def scan_release_binary_blob(data: bytes, label: str,
                             rules: Sequence[Rule]) -> list[Finding]:
    """Scan release data without treating short opaque bytes as labels."""
    signature_ranges: list[tuple[int, int]] = []
    opaque_ranges: list[tuple[int, int]] = []
    ranges = _macho_non_string_section_ranges(data)
    if ranges is not None:
        symbol_ranges = _macho_symbol_record_ranges(data)
        signature_ranges = _macho_code_signature_ranges(data)
        if symbol_ranges is None or signature_ranges is None:
            raise ValueError("inconsistent Mach-O release-binary parser")
        ranges.extend(symbol_ranges)
    if ranges is None:
        ranges = _elf_executable_ranges(data)
        opaque_ranges = _elf_opaque_metadata_ranges(data) or []
    if ranges is None:
        return scan_blob(data, label, rules, binary=True)
    searchable = bytearray(data)
    for start, end in signature_ranges + opaque_ranges:
        searchable[start:end] = b"\0" * (end - start)
    # Machine instructions, pointers, and linker records can form isolated
    # short labels by chance. The worktree scan still checks their source, and
    # longer byte sequences remain visible so metadata cannot hide phrases.
    for start, end in ranges:
        for match in re.finditer(rb"[A-Za-z0-9]+", data[start:end]):
            token_start = start + match.start()
            token_end = start + match.end()
            starts_inside_token = (
                token_start == start and start > 0 and
                chr(data[start - 1]).isascii() and
                chr(data[start - 1]).isalnum()
            )
            ends_inside_token = (
                token_end == end and end < len(data) and
                chr(data[end]).isascii() and chr(data[end]).isalnum()
            )
            if (not starts_inside_token and not ends_inside_token and
                    token_end - token_start <= 3):
                searchable[token_start:token_end] = b"\0" * (
                    token_end - token_start
                )
    return scan_blob(bytes(searchable), label, rules, binary=True)


def _walk_paths(root: Path, paths: Iterable[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for item in paths:
        path = item if item.is_absolute() else root / item
        if path.is_symlink() or path.is_file():
            candidates = (path,)
        elif path.is_dir():
            candidates = (
                candidate for candidate in path.rglob("*")
                if candidate.is_symlink() or candidate.is_file()
            )
        else:
            continue
        for candidate in candidates:
            absolute = candidate.absolute()
            if absolute not in seen:
                seen.add(absolute)
                yield absolute


def _relative_label(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def scan_paths(root: Path, paths: Iterable[Path], rules: Sequence[Rule],
               *, binary: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for path in _walk_paths(root, paths):
        label = _relative_label(root, path)
        findings.extend(scan_blob(label.encode("utf-8"), f"filename:{label}",
                                  rules))
        if path.is_symlink():
            target = os.readlink(path)
            findings.extend(scan_blob(target.encode("utf-8"),
                                      f"symlink:{label}", rules))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"cannot read {label}: {exc}") from exc
        findings.extend(scan_blob(data, label, rules, binary=binary))
    return findings


def scan_release_binary_paths(root: Path, paths: Iterable[Path],
                              rules: Sequence[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for item in paths:
        path = item if item.is_absolute() else root / item
        if not path.is_symlink() and not path.is_file():
            raise RuntimeError(f"release binary is missing or not a file: {item}")
        label = _relative_label(root, path)
        findings.extend(scan_blob(label.encode("utf-8"),
                                  f"filename:{label}", rules))
        if path.is_symlink():
            target = os.readlink(path)
            findings.extend(scan_blob(target.encode("utf-8"),
                                      f"symlink:{label}", rules))
            try:
                path = path.resolve(strict=True)
            except OSError as exc:
                raise RuntimeError(
                    f"cannot resolve release binary {label}: {exc}"
                ) from exc
            if not path.is_file():
                raise RuntimeError(
                    f"release binary target is not a file: {label}"
                )
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"cannot read {label}: {exc}") from exc
        findings.extend(scan_release_binary_blob(data, label, rules))
    return findings


def _git(root: Path, args: Sequence[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _zero_paths(data: bytes) -> list[Path]:
    return [Path(value.decode("utf-8", "surrogateescape"))
            for value in data.split(b"\0") if value]


def scan_worktree(root: Path, rules: Sequence[Rule]) -> list[Finding]:
    candidates = _zero_paths(_git(
        root, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ))
    findings = scan_paths(root, candidates, rules)

    staged = _zero_paths(_git(
        root, ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
    ))
    for path in staged:
        label = path.as_posix()
        data = _git(root, ["show", f":{label}"])
        findings.extend(scan_blob(data, f"index:{label}", rules))
        findings.extend(scan_blob(label.encode("utf-8"),
                                  f"index-filename:{label}", rules))
    return findings


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Check public candidate content against the repository vocabulary manifest."
    )
    parser.add_argument("paths", nargs="*", type=Path,
                        help="specific files or directories instead of the Git worktree")
    parser.add_argument("--root", type=Path, default=root_default)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--generated-root", action="append", default=[], type=Path,
                        help="generated-source directory to inspect")
    parser.add_argument(
        "--release-binary", action="append", default=[], type=Path,
        help="release executable or library to inspect outside instruction sections",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    manifest = args.manifest or root / "tools" / "forbidden_trace_manifest.json"
    try:
        rules, _retained = load_manifest(manifest)
        if args.paths:
            findings = scan_paths(root, args.paths, rules)
        else:
            findings = scan_worktree(root, rules)
        findings.extend(scan_paths(root, args.generated_root, rules))
        findings.extend(scan_release_binary_paths(
            root, args.release_binary, rules
        ))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"trace gate error: {exc}", file=sys.stderr)
        return 2

    unique = sorted(set(findings))
    for finding in unique:
        print(
            f"{finding.location}: {finding.category} ({finding.rule_id})",
            file=sys.stderr,
        )
    if unique:
        print(f"trace gate: FAIL ({len(unique)} finding(s))", file=sys.stderr)
        return 1
    print("trace gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
