# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the public-tree vocabulary gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO / "tools" / "forbidden_trace_scan.py"
SPEC = importlib.util.spec_from_file_location("forbidden_trace_scan", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SCAN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCAN
SPEC.loader.exec_module(SCAN)
MANIFEST = REPO / "tools" / "forbidden_trace_manifest.json"


def _synthetic_rule() -> object:
    digest = hashlib.sha256(b"synthetic marker").digest()
    return SCAN.Rule(
        "synthetic_001",
        "synthetic_fixture",
        None,
        (SCAN.TokenHash(2, digest),),
    )


def _text_only_rule() -> object:
    return SCAN.Rule(
        "synthetic_text_only",
        "synthetic_fixture",
        SCAN.re.compile(r"(?<![A-Za-z0-9])e" + "17" +
                        r"(?![A-Za-z0-9])",
                        SCAN.re.ASCII | SCAN.re.IGNORECASE),
        (),
        True,
    )


def _synthetic_macho64(text: bytes, cstrings: bytes) -> bytes:
    header_size = 32
    section_size = 80
    command_size = 72 + 2 * section_size
    text_offset = header_size + command_size
    cstring_offset = text_offset + len(text)
    payload_size = len(text) + len(cstrings)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1,
        command_size, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, command_size, b"__TEXT", 0x1000,
        payload_size, text_offset, payload_size, 7, 5, 2, 0,
    )
    text_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x1000,
        len(text), text_offset, 2, 0, 0, 0x80000400, 0, 0, 0,
    )
    cstring_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__cstring", b"__TEXT",
        0x1000 + len(text),
        len(cstrings), cstring_offset, 0, 0, 0, 0x2, 0, 0, 0,
    )
    return header + segment + text_section + cstring_section + text + cstrings


def _synthetic_macho64_with_signature(
        text: bytes, cstrings: bytes, signature: bytes) -> bytes:
    header_size = 32
    section_size = 80
    signature_command_size = 16
    segment_command_size = 72 + 2 * section_size
    command_size = segment_command_size + signature_command_size
    text_offset = header_size + command_size
    cstring_offset = text_offset + len(text)
    signature_offset = cstring_offset + len(cstrings)
    payload_size = len(text) + len(cstrings)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2,
        command_size, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, segment_command_size, b"__TEXT", 0x1000,
        payload_size, text_offset, payload_size, 7, 5, 2, 0,
    )
    text_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x1000,
        len(text), text_offset, 2, 0, 0, 0x80000400, 0, 0, 0,
    )
    cstring_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__cstring", b"__TEXT",
        0x1000 + len(text),
        len(cstrings), cstring_offset, 0, 0, 0, 0x2, 0, 0, 0,
    )
    signature_command = struct.pack(
        "<IIII", 0x1D, signature_command_size,
        signature_offset, len(signature),
    )
    return (header + segment + text_section + cstring_section +
            signature_command + text + cstrings + signature)


def _synthetic_macho64_with_const(
        text: bytes, cstrings: bytes, const_data: bytes) -> bytes:
    header_size = 32
    section_size = 80
    command_size = 72 + 3 * section_size
    text_offset = header_size + command_size
    cstring_offset = text_offset + len(text)
    const_offset = cstring_offset + len(cstrings)
    payload_size = len(text) + len(cstrings) + len(const_data)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1,
        command_size, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, command_size, b"__TEXT", 0x1000,
        payload_size, text_offset, payload_size, 7, 5, 3, 0,
    )
    text_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x1000,
        len(text), text_offset, 2, 0, 0, 0x80000400, 0, 0, 0,
    )
    cstring_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__cstring", b"__TEXT",
        0x1000 + len(text), len(cstrings), cstring_offset,
        0, 0, 0, 0x2, 0, 0, 0,
    )
    const_section = struct.pack(
        "<16s16sQQIIIIIIII", b"__const", b"__TEXT",
        0x1000 + len(text) + len(cstrings), len(const_data), const_offset,
        0, 0, 0, 0, 0, 0, 0,
    )
    return (header + segment + text_section + cstring_section + const_section +
            text + cstrings + const_data)


def _synthetic_macho64_with_symbols(symbols: bytes, strings: bytes) -> bytes:
    if len(symbols) == 0 or len(symbols) % 16 != 0:
        raise ValueError("Mach-O 64-bit symbol entries must be 16-byte records")
    header_size = 32
    segment_size = 72
    symtab_size = 24
    command_size = segment_size + symtab_size
    symbol_offset = header_size + command_size
    string_offset = symbol_offset + len(symbols)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2,
        command_size, 0, 0,
    )
    linkedit = struct.pack(
        "<II16sQQQQiiII", 0x19, segment_size, b"__LINKEDIT", 0x1000,
        len(symbols) + len(strings), symbol_offset,
        len(symbols) + len(strings), 7, 1, 0, 0,
    )
    symtab = struct.pack(
        "<IIIIII", 0x2, symtab_size, symbol_offset, len(symbols) // 16,
        string_offset, len(strings),
    )
    return header + linkedit + symtab + symbols + strings


def _synthetic_fat_macho64(text: bytes, cstrings: bytes) -> bytes:
    thin = _synthetic_macho64(text, cstrings)
    slice_offset = 8 + 20
    header = struct.pack(
        ">IIiiIII", 0xCAFEBABE, 1, 0x0100000C, 0, slice_offset,
        len(thin), 2,
    )
    return header + thin


def _synthetic_sectionless_macho64(text: bytes) -> bytes:
    header_size = 32
    command_size = 72
    text_offset = header_size + command_size
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1,
        command_size, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, command_size, b"__TEXT", 0x1000,
        len(text), text_offset, len(text), 7, 5, 0, 0,
    )
    return header + segment + text


def _synthetic_elf64(text: bytes, strings: bytes) -> bytes:
    header_size = 64
    program_size = 56
    text_offset = header_size + program_size
    string_offset = text_offset + len(text)
    section_offset = string_offset + len(strings)
    identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", identity, 2, 62, 1, 0, header_size,
        section_offset, 0, header_size, program_size, 1, 64, 3, 0,
    )
    program = struct.pack(
        "<IIQQQQQQ", 1, 0x5, text_offset, 0x1000, 0x1000,
        len(text), len(text), 0x1000,
    )
    null_section = b"\0" * 64
    text_section = struct.pack(
        "<IIQQQQIIQQ", 0, 1, 0x6, 0x1000, text_offset, len(text),
        0, 0, 4, 0,
    )
    string_section = struct.pack(
        "<IIQQQQIIQQ", 0, 1, 0x2, 0x2000, string_offset,
        len(strings), 0, 0, 1, 0,
    )
    return (header + program + text + strings + null_section + text_section +
            string_section)


def _synthetic_stripped_elf64(text: bytes) -> bytes:
    header_size = 64
    program_size = 56
    text_offset = header_size + program_size
    identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", identity, 2, 62, 1, 0, header_size,
        0, 0, header_size, program_size, 1, 0, 0, 0,
    )
    program = struct.pack(
        "<IIQQQQQQ", 1, 0x5, text_offset, 0x1000, 0x1000,
        len(text), len(text), 0x1000,
    )
    return header + program + text


class VocabularyGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules, cls.retained = SCAN.load_manifest(MANIFEST)

    def test_manifest_contains_only_digests_and_neutral_structural_regexes(self) -> None:
        raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(raw["schema_version"], 2)
        for item in raw["rules"]:
            self.assertNotIn("regex_b64", item)
            self.assertNotIn("history_prefilter_any_b64", item)
            for literal in item.get("token_sha256", []):
                self.assertRegex(literal["digest"], r"^[0-9a-f]{64}$")

    def test_retained_product_identifiers_are_accepted(self) -> None:
        for identifier in self.retained:
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    SCAN.scan_blob(identifier.encode(), "fixture", self.rules), []
                )

    def test_synthetic_token_digest_rejects_only_the_exact_phrase(self) -> None:
        rule = _synthetic_rule()
        findings = SCAN.scan_blob(b"prefix synthetic-marker suffix", "fixture", [rule])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "synthetic_fixture")
        self.assertNotIn("synthetic marker", str(findings[0]))
        self.assertEqual(SCAN.scan_blob(b"synthetic markers", "fixture", [rule]), [])

    def test_synthetic_prefix_and_following_token_conditions(self) -> None:
        prefix = SCAN.TokenHash(
            1,
            hashlib.sha256(b"alpha").digest(),
            5,
            SCAN.re.compile(r"[0-9]+", SCAN.re.ASCII),
        )
        following = SCAN.TokenHash(
            1,
            hashlib.sha256(b"phase").digest(),
            next_tokens=(SCAN.re.compile(r"[0-9]+", SCAN.re.ASCII),),
        )
        rule = SCAN.Rule("synthetic_002", "synthetic_fixture", None,
                         (prefix, following))
        self.assertEqual(len(SCAN.scan_blob(b"alpha42", "fixture", [rule])), 1)
        self.assertEqual(len(SCAN.scan_blob(b"phase 42", "fixture", [rule])), 1)
        self.assertEqual(SCAN.scan_blob(b"alpha phase", "fixture", [rule]), [])

    def test_shared_hash_windows_preserve_rule_item_order_and_locations(self) -> None:
        phrase = hashlib.sha256(b"synthetic marker").digest()
        prefix = SCAN.TokenHash(
            1,
            hashlib.sha256(b"alpha").digest(),
            5,
            SCAN.re.compile(r"[0-9]+", SCAN.re.ASCII),
        )
        following = SCAN.TokenHash(
            2,
            phrase,
            next_tokens=(SCAN.re.compile(r"tail", SCAN.re.ASCII),),
        )
        rules = (
            SCAN.Rule(
                "synthetic_a",
                "category_a",
                SCAN.re.compile(r"synthetic[- ]marker", SCAN.re.ASCII | SCAN.re.I),
                (SCAN.TokenHash(2, phrase), prefix),
            ),
            SCAN.Rule(
                "synthetic_b",
                "category_b",
                SCAN.re.compile(r"marker", SCAN.re.ASCII | SCAN.re.I),
                (following,),
            ),
        )
        findings = SCAN.scan_blob(
            b"zero SYNTHETIC-marker tail\nalpha42 alphaXX synthetic marker\n",
            "fixture",
            rules,
        )
        self.assertEqual(
            findings,
            [
                SCAN.Finding("fixture:1:6", "category_a", "synthetic_a"),
                SCAN.Finding("fixture:2:17", "category_a", "synthetic_a"),
                SCAN.Finding("fixture:1:6", "category_a", "synthetic_a"),
                SCAN.Finding("fixture:2:17", "category_a", "synthetic_a"),
                SCAN.Finding("fixture:2:1", "category_a", "synthetic_a"),
                SCAN.Finding("fixture:1:16", "category_b", "synthetic_b"),
                SCAN.Finding("fixture:2:27", "category_b", "synthetic_b"),
                SCAN.Finding("fixture:1:6", "category_b", "synthetic_b"),
            ],
        )

    def test_many_rules_scan_a_realistic_blob_within_a_bounded_time(self) -> None:
        rules = []
        for index in range(64):
            token_count = index % 4 + 1
            phrase = " ".join(["absent"] * token_count).encode("ascii")
            rules.append(SCAN.Rule(
                f"bounded_{index}",
                "synthetic_fixture",
                None,
                (SCAN.TokenHash(token_count, hashlib.sha256(phrase).digest()),),
            ))
        payload = b"ordinary public source tokens\n" * 65536
        started = time.monotonic()
        findings = SCAN.scan_blob(payload, "fixture", rules, binary=True)
        elapsed = time.monotonic() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 5.0)

    def test_generic_sensitive_structures_are_narrow_and_case_sensitive(self) -> None:
        rejected = (
            "10." + "23.4.5",
            "192." + "168.64.2_3389.pem",
            "/" + "Users/example/work/source.c",
            "/" + "home/example/work/source.c",
            "(user=" + "ExampleAccount)",
            bytes.fromhex("57494e2d5244502d4c4142").decode("ascii"),
            bytes.fromhex("5465737441646d696e").decode("ascii"),
            bytes.fromhex("73387563466369623979476776783233").decode("ascii"),
        )
        for sample in rejected:
            with self.subTest(sample=sample):
                findings = SCAN.scan_blob(sample.encode(), "fixture", self.rules)
                self.assertIn("sensitive_value",
                              {finding.category for finding in findings})
        accepted = (
            "// Arrow/Home/End navigation",
            '"--user="',
            "(user=%s)",
        )
        for sample in accepted:
            with self.subTest(sample=sample):
                self.assertEqual(
                    [item for item in SCAN.scan_blob(
                        sample.encode(), "fixture", self.rules
                    ) if item.category == "sensitive_value"],
                    [],
                )

    def test_ordinary_review_loop_and_protocol_terms_are_accepted(self) -> None:
        samples = (
            "required counsel review",
            "event loop",
            "reviewed dependency",
            "SRP M1 and M2 proofs",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(
                    SCAN.scan_blob(sample.encode(), "fixture", self.rules), []
                )

    def test_compact_process_identifiers_are_rejected(self) -> None:
        samples = tuple(
            bytes.fromhex(encoded).decode("ascii")
            for encoded in (
                "7265766965773139",
                "7265766965772d3139",
                "7265766965775f3139",
                "7231395f68656c706572",
                "723139735f63617074757265",
            )
        )
        for sample in samples:
            with self.subTest(sample=sample):
                findings = SCAN.scan_blob(sample.encode(), "fixture", self.rules)
                self.assertIn(
                    "process_archaeology",
                    {finding.category for finding in findings},
                )

    def test_release_review_shorthand_is_rejected(self) -> None:
        samples = tuple(
            bytes.fromhex(encoded).decode("ascii")
            for encoded in ("52454c2e31", "52454c2d3132", "4d37")
        )
        for sample in samples:
            with self.subTest(sample=sample):
                findings = SCAN.scan_blob(sample.encode(), "fixture", self.rules)
                self.assertIn(
                    "process_archaeology",
                    {finding.category for finding in findings},
                )

    def test_standalone_phase_and_context_residue_is_rejected(self) -> None:
        samples = tuple(
            bytes.fromhex(encoded).decode("ascii")
            for encoded in (
                "4538",
                "653137",
                "45313861",
                "6e6f74652d6531372d6d61702e63",
                "726576696577204c3238",
                "7265766965775f6974656d5f4832",
                "726576696577206974656d204d38",
                "4831362066726f6d20726576696577",
                "706565722072657669657773",
                "72657665727365206175646974",
                "66756c6c20686973746f727920696e20676974",
                "646f206e6f742072652d657870616e64",
            )
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(
                    SCAN.scan_blob(sample.encode(), "fixture", self.rules)
                )

    def test_empirical_provenance_context_is_rejected(self) -> None:
        samples = tuple(
            bytes.fromhex(encoded).decode("ascii")
            for encoded in (
                "7265736561726368206d756c7469206672616d65",
                "726573656172636820736b6970",
                "726573656172636820736f66742070617468",
                "7265736561726368206b6565702064656d7578",
                "726573656172636820736f6c696420626c61636b",
                "726573656172636820746f6f6c73",
                "6578706572696d656e74206d6174657269616c",
                "6578706572696d656e7420632073206b6e6f6273",
                "617574686f72697a65642063617074757265",
                "617574686f72697a656420766d2063617074757265",
                "776972652070726f6265",
                "6c69766520706c61696e2064756d7073",
                "646976657267656e636520696e737472756d656e746174696f6e",
                "6f627365727665642061636b",
                "6f62736572766564204170706c65",
                "6f6273657276656420656e76656c6f7065",
                "6f627365727665642066697665",
                "6f6273657276656420696d616765",
                "6f627365727665642073657373696f6e",
                "6f62736572766564206f6e206c697665",
                "6368616c6c656e6765206f62736572766564",
                "4170706c65206f62736572766564",
                "6361707475726564204170706c65",
                "636170747572656420636c69656e74",
                "6361707475726564206576657279",
                "6361707475726564206c697665",
                "6361707475726564206d6f6465726e",
                "6361707475726564206d73673134",
                "63617074757265642070617468",
                "636170747572656420736572766572",
                "63617074757265642074797065",
                "63617074757265642076616c756573",
                "63617074757265642077697265",
                "63617074757265642039",
                "6e6f7420796574206361707475726564",
            )
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(
                    SCAN.scan_blob(sample.encode(), "fixture", self.rules)
                )

    def test_broad_runtime_policy_and_gate_terms_are_accepted(self) -> None:
        samples = tuple(
            bytes.fromhex(encoded).decode("ascii")
            for encoded in (
                "4731372052303120463038204532452065333320653337",
                "63617074757265207363686564756c6572207068617365206f62736572766174696f6e207374617465",
                "4641525345455f4150504c455f4d56535f5245534541524348",
                "4641525345455f4150504c455f4558504552494d454e54",
                "4641525345455f4d56535f5452414345",
                "746872656174206d6f64656c",
                "6f776e657273686970206d6f64656c",
                "646570656e64656e63792070726f76656e616e6365",
                "5246432d6465726976656420636c65616e2d726f6f6d20736f757263652d706f6c6963792074657874",
                "736f6c696420626c61636b2072656420677265656e207768697465206d69642d67726179",
                "6f7264696e61727920726576696577",
                "736563757269747920726576696577",
                "7065657220726576696577",
                "6f6273657276656420636f756e742069732076697369626c65",
                "6361707475726564203d20726573756c742e7374646f7574",
                "6c6976652064756d7020656e61626c6564206279202d2d64756d702d6672616d65",
            )
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(
                    SCAN.scan_blob(sample.encode(), "fixture", self.rules), []
                )

    def test_text_only_rules_skip_binary_data(self) -> None:
        rule = _text_only_rule()
        phase = bytes.fromhex("7072656669782045313720737566666978")
        self.assertTrue(SCAN.scan_blob(phase, "fixture", [rule]))
        self.assertEqual(
            SCAN.scan_blob(b"\0" + phase + b"\0", "fixture", [rule],
                           binary=True),
            [],
        )
        self.assertEqual(
            SCAN.scan_blob(b"prefix \xff " + bytes.fromhex("453137"),
                           "fixture", [rule], binary=True),
            [],
        )
        self.assertTrue(
            SCAN.scan_blob(
                b"\0synthetic-marker\0", "fixture", [_synthetic_rule()],
                binary=True,
            )
        )

    def test_release_binary_scan_ignores_instruction_bytes(self) -> None:
        markers = (bytes.fromhex("4d37"), bytes.fromhex("523139"))
        builders = (
            _synthetic_macho64, _synthetic_fat_macho64, _synthetic_elf64,
        )
        for marker in markers:
            rule = SCAN.Rule(
                "synthetic_machine_code", "synthetic_fixture", None,
                (SCAN.TokenHash(
                    1, hashlib.sha256(marker.lower()).digest()
                ),),
            )
            for builder in builders:
                with self.subTest(marker=marker.hex(),
                                  format=builder.__name__):
                    binary = builder(marker + b"\0", b"public\0")
                    self.assertEqual(
                        SCAN.scan_release_binary_blob(
                            binary, "candidate", [rule]
                        ),
                        [],
                    )

    def test_release_binary_scan_still_rejects_string_data(self) -> None:
        markers = (bytes.fromhex("4d37"), bytes.fromhex("523139"))
        builders = (
            _synthetic_macho64, _synthetic_fat_macho64, _synthetic_elf64,
        )
        for marker in markers:
            rule = SCAN.Rule(
                "synthetic_string_data", "synthetic_fixture", None,
                (SCAN.TokenHash(
                    1, hashlib.sha256(marker.lower()).digest()
                ),),
            )
            for builder in builders:
                with self.subTest(marker=marker.hex(),
                                  format=builder.__name__):
                    binary = builder(b"safe\0", marker + b"\0")
                    findings = SCAN.scan_release_binary_blob(
                        binary, "candidate", [rule]
                    )
                    self.assertEqual(len(findings), 1)
                    self.assertIn(":byte:", findings[0].location)

    def test_release_binary_scan_distinguishes_macho_symbols_from_strings(
            self) -> None:
        marker = bytes.fromhex("4d37")
        rule = SCAN.Rule(
            "synthetic_symbol_bytes", "synthetic_fixture", None,
            (SCAN.TokenHash(
                1, hashlib.sha256(marker.lower()).digest()
            ),),
        )
        symbol_marker = b"\0" * 8 + marker + b"\0" * 6
        binary = _synthetic_macho64_with_symbols(symbol_marker, b"public\0")
        self.assertEqual(
            SCAN.scan_release_binary_blob(binary, "candidate", [rule]), []
        )

        safe_symbol = b"\0" * 16
        binary = _synthetic_macho64_with_symbols(
            safe_symbol, b"\0" + marker + b"\0"
        )
        findings = SCAN.scan_release_binary_blob(binary, "candidate", [rule])
        self.assertEqual(len(findings), 1)
        self.assertIn(":byte:", findings[0].location)

    def test_release_binary_scan_ignores_macho_code_signature_blob(self) -> None:
        binary = _synthetic_macho64_with_signature(
            b"safe\0", b"public\0", b"\0synthetic-marker\0"
        )
        self.assertEqual(
            SCAN.scan_release_binary_blob(
                binary, "candidate", [_synthetic_rule()]
            ),
            [],
        )

    def test_release_binary_scan_ignores_short_macho_const_bytes(self) -> None:
        marker = bytes.fromhex("4d37")
        rule = SCAN.Rule(
            "synthetic_const_data", "synthetic_fixture", None,
            (SCAN.TokenHash(
                1, hashlib.sha256(marker.lower()).digest()
            ),),
        )
        binary = _synthetic_macho64_with_const(
            b"safe\0", b"public\0", b"\0" + marker + b"\xff"
        )
        self.assertEqual(
            SCAN.scan_release_binary_blob(binary, "candidate", [rule]), []
        )

    def test_release_binary_scan_unknown_format_remains_fail_closed(self) -> None:
        findings = SCAN.scan_release_binary_blob(
            b"\0synthetic-marker\0", "candidate", [_synthetic_rule()]
        )
        self.assertEqual(len(findings), 1)

    def test_release_binary_scan_rejects_malformed_known_format(self) -> None:
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes.fromhex("cffaedfe"), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_does_not_hide_long_exec_section_data(self) -> None:
        binary = bytearray(_synthetic_macho64(
            b"safe\0", b"synthetic-marker\0"
        ))
        cstring_section_flags = 32 + 72 + 80 + 64
        struct.pack_into("<I", binary, cstring_section_flags, 0x80000400)
        findings = SCAN.scan_release_binary_blob(
            bytes(binary), "candidate", [_synthetic_rule()]
        )
        self.assertEqual(len(findings), 1)

    def test_release_binary_scan_rejects_exec_section_outside_segment(self) -> None:
        binary = bytearray(_synthetic_macho64(b"safe\0", b"public\0"))
        text_section_file_offset = 32 + 72 + 48
        struct.pack_into("<I", binary, text_section_file_offset, 0)
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes(binary), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_rejects_exec_nobits_section(self) -> None:
        binary = bytearray(_synthetic_elf64(b"safe\0", b"public\0"))
        section_offset = struct.unpack_from("<Q", binary, 40)[0]
        text_section_type = section_offset + 64 + 4
        struct.pack_into("<I", binary, text_section_type, 8)
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes(binary), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_stripped_elf_remains_full_scan(self) -> None:
        marker = bytes.fromhex("4d37")
        rule = SCAN.Rule(
            "synthetic_stripped_elf", "synthetic_fixture", None,
            (SCAN.TokenHash(1, hashlib.sha256(marker.lower()).digest()),),
        )
        binary = _synthetic_stripped_elf64(marker + b"\0")
        self.assertEqual(len(SCAN.scan_release_binary_blob(
            binary, "candidate", [rule]
        )), 1)

    def test_release_binary_scan_sectionless_macho_remains_full_scan(self) -> None:
        marker = bytes.fromhex("4d37")
        rule = SCAN.Rule(
            "synthetic_sectionless_macho", "synthetic_fixture", None,
            (SCAN.TokenHash(1, hashlib.sha256(marker.lower()).digest()),),
        )
        binary = _synthetic_sectionless_macho64(marker + b"\0")
        self.assertEqual(len(SCAN.scan_release_binary_blob(
            binary, "candidate", [rule]
        )), 1)

    def test_release_binary_scan_rejects_macho_virtual_mismatch(self) -> None:
        binary = bytearray(_synthetic_macho64(b"safe\0", b"public\0"))
        text_section_address = 32 + 72 + 32
        struct.pack_into("<Q", binary, text_section_address, 0x3000)
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes(binary), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_rejects_macho_segment_name_mismatch(self) -> None:
        binary = bytearray(_synthetic_macho64(b"safe\0", b"public\0"))
        text_section_segment_name = 32 + 72 + 16
        binary[text_section_segment_name:text_section_segment_name + 16] = (
            b"__DATA" + b"\0" * 10
        )
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes(binary), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_rejects_elf_exec_without_alloc(self) -> None:
        binary = bytearray(_synthetic_elf64(b"safe\0", b"public\0"))
        section_offset = struct.unpack_from("<Q", binary, 40)[0]
        text_section_flags = section_offset + 64 + 8
        struct.pack_into("<Q", binary, text_section_flags, 0x4)
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes(binary), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_rejects_elf_virtual_mismatch(self) -> None:
        binary = bytearray(_synthetic_elf64(b"safe\0", b"public\0"))
        section_offset = struct.unpack_from("<Q", binary, 40)[0]
        text_section_address = section_offset + 64 + 16
        struct.pack_into("<Q", binary, text_section_address, 0x3000)
        with self.assertRaises(ValueError):
            SCAN.scan_release_binary_blob(
                bytes(binary), "candidate", [_synthetic_rule()]
            )

    def test_release_binary_scan_accepts_elf_extended_program_count(self) -> None:
        marker = bytes.fromhex("4d37")
        rule = SCAN.Rule(
            "synthetic_extended_elf", "synthetic_fixture", None,
            (SCAN.TokenHash(1, hashlib.sha256(marker.lower()).digest()),),
        )
        binary = bytearray(_synthetic_elf64(marker + b"\0", b"public\0"))
        section_offset = struct.unpack_from("<Q", binary, 40)[0]
        struct.pack_into("<H", binary, 56, 0xffff)
        struct.pack_into("<I", binary, section_offset + 44, 1)
        self.assertEqual(SCAN.scan_release_binary_blob(
            bytes(binary), "candidate", [rule]
        ), [])

    def test_release_binary_paths_require_an_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaises(RuntimeError):
                SCAN.scan_release_binary_paths(
                    root, [Path("missing")], [_synthetic_rule()]
                )

    def test_release_binary_paths_scan_symlink_target_and_reject_dangling(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target.bin"
            target.write_bytes(b"\0synthetic-marker\0")
            link = root / "candidate"
            link.symlink_to(target.name)
            findings = SCAN.scan_release_binary_paths(
                root, [Path(link.name)], [_synthetic_rule()]
            )
            self.assertEqual(len(findings), 1)
            target.unlink()
            with self.assertRaises(RuntimeError):
                SCAN.scan_release_binary_paths(
                    root, [Path(link.name)], [_synthetic_rule()]
                )

    def test_required_and_ordinary_vocabulary_is_accepted(self) -> None:
        samples = (
            "capture a framebuffer",
            "captured in a local buffer",
            "rfb_capture_scheduler_publish",
            "input quality is inferred from the event",
            "cryptographic key derivation",
            "live dump enabled by --dump-frame",
            "a display generated by the application",
            "initialize a GPT disk partition",
            "generated by the example generator",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(
                    SCAN.scan_blob(sample.encode(), "fixture", self.rules), []
                )

    def test_disallowed_source_policy_phrases_are_rejected(self) -> None:
        samples = (
            bytes.fromhex(
                "70726f6a6563742d6f776e6564206361707475726573"
            ).decode("ascii"),
            bytes.fromhex(
                "7265646163746564207472616e73637269707473"
            ).decode("ascii"),
        )
        for sample in samples:
            with self.subTest(sample=sample):
                findings = SCAN.scan_blob(
                    sample.encode(), "fixture", self.rules
                )
                self.assertIn(
                    "source_policy_trace",
                    {finding.category for finding in findings},
                )

    def test_synthetic_provenance_phrase_remains_rejected(self) -> None:
        digest = hashlib.sha256(b"synthetic provenance marker").digest()
        rule = SCAN.Rule(
            "synthetic_003",
            "synthetic_fixture",
            None,
            (SCAN.TokenHash(3, digest),),
        )
        findings = SCAN.scan_blob(
            b"prefix synthetic-provenance-marker suffix", "fixture", [rule]
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "synthetic_fixture")
        self.assertEqual(
            SCAN.scan_blob(
                b"synthetic provenance markers", "fixture", [rule]
            ),
            [],
        )

    def test_content_filename_symlink_generated_and_binary_are_scanned(self) -> None:
        sample = "synthetic-marker"
        rules = [_synthetic_rule()]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            content = root / "content.txt"
            content.write_text(sample, encoding="utf-8")
            named = root / (sample + ".txt")
            named.write_text("safe", encoding="utf-8")
            link = root / "linked"
            os.symlink(sample, link)
            generated = root / "generated"
            generated.mkdir()
            (generated / "unit.c").write_text(sample, encoding="utf-8")
            binary = root / "candidate.bin"
            binary.write_bytes(b"\x00" + sample.encode() + b"\x00")

            findings = SCAN.scan_paths(root, [content, named, link], rules)
            locations = {finding.location.split(":", 1)[0] for finding in findings}
            self.assertIn("content.txt", locations)
            self.assertIn("filename", locations)
            self.assertIn("symlink", locations)
            self.assertTrue(SCAN.scan_paths(root, [generated], rules))
            binary_findings = SCAN.scan_paths(root, [binary], rules, binary=True)
            self.assertTrue(any(":byte:" in item.location
                                for item in binary_findings))

    def test_evidence_binary_artifact_paths_are_rejected_narrowly(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "docs" / "gates" / "interop-evidence" / "neutral"
            fixtures = root / "tests" / "fixtures"
            evidence.mkdir(parents=True)
            fixtures.mkdir(parents=True)
            blocked = (evidence / "vector.bin", evidence / "frame.png")
            allowed = (evidence / "README.txt", fixtures / "vector.bin",
                       fixtures / "frame.png")
            for path in blocked + allowed:
                path.write_bytes(b"safe")

            findings = SCAN.scan_paths(root, [root], self.rules)
            rejected = {
                item.location.split(":", 2)[1]
                for item in findings
                if item.location.startswith("filename:")
            }
            self.assertEqual(
                rejected,
                {
                    "docs/gates/interop-evidence/neutral/vector.bin",
                    "docs/gates/interop-evidence/neutral/frame.png",
                },
            )

    def test_apple_trace_report_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "docs" / "apple" / "type36-0450-evidence.md"
            report.parent.mkdir(parents=True)
            report.write_text("safe\n", encoding="utf-8")

            findings = SCAN.scan_paths(root, [report], self.rules)
            self.assertTrue(any(
                item.location.startswith(
                    "filename:docs/apple/type36-0450-evidence.md"
                )
                for item in findings
            ))

    def test_staged_content_is_scanned_when_worktree_copy_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q", "-b", "master"], cwd=root,
                           check=True)
            path = root / "note.txt"
            path.write_text("safe\n", encoding="utf-8")
            subprocess.run(["git", "add", "note.txt"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c",
                 "user.email=test@example.invalid", "commit", "-qm", "seed"],
                cwd=root,
                check=True,
            )
            path.write_text("synthetic-marker\n", encoding="utf-8")
            subprocess.run(["git", "add", "note.txt"], cwd=root, check=True)
            path.write_text("safe\n", encoding="utf-8")

            findings = SCAN.scan_worktree(root, [_synthetic_rule()])
            self.assertTrue(any(item.location.startswith("index:note.txt:")
                                for item in findings))


if __name__ == "__main__":
    unittest.main()
