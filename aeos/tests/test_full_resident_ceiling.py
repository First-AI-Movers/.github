"""The one programme block that has no calendar end: a full resident ceiling.

``derivation_policy.is_full_resident_ceiling`` restates agent-toolkit's ``is_full_ceiling``
(``scripts/agent_relay/standing_ceiling.py``), because the gate cannot import it. Two readers
of one class must not drift apart, so the verdicts are pinned as data:
``full-resident-ceiling-vectors.json`` holds each case and the verdict agent-toolkit's function
gave for it at the commit the file names. This module asserts the judge gives the same verdict,
so a change to the judge that moves any pinned verdict fails here. The file is written to be
carried byte for byte into agent-toolkit, where the same assertion over ``is_full_ceiling``
catches a change on that side. The vectors pin the cases they name; they are not a proof that the
two readers agree on every input.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import derivation_policy as dp  # noqa: E402

VECTORS = os.path.join(HERE, "full-resident-ceiling-vectors.json")


def load_vectors() -> dict:
    with open(VECTORS, encoding="utf-8") as handle:
        return json.load(handle)


def document_of(vectors: dict, case: dict):
    """The block a case describes: ``document`` as it stands, or the base without the keys in
    ``drop`` and then updated with ``set``."""
    if "document" in case:
        return copy.deepcopy(case["document"])
    block = {key: copy.deepcopy(value) for key, value in vectors["base"].items() if key not in case.get("drop", ())}
    block.update(copy.deepcopy(case.get("set", {})))
    return block


class FullResidentCeilingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = load_vectors()
        self.base = self.vectors["base"]

    @staticmethod
    def verdict(value):
        """The judge's answer, or the exception it raised: a raise must fail an assertion, not error out."""
        try:
            return dp.is_full_resident_ceiling(value)
        except Exception as exc:  # noqa: BLE001 -- the point is that nothing may escape
            return exc

    def test_the_vector_file_is_the_shape_this_reader_expects(self) -> None:
        self.assertEqual(self.vectors["schema"], "aeos-full-resident-ceiling-vectors/v1")
        self.assertEqual(set(self.vectors), {"schema", "oracle", "how_to_read", "definition", "base", "cases"})
        names = [case["name"] for case in self.vectors["cases"]]
        self.assertEqual(len(names), len(set(names)))
        for case in self.vectors["cases"]:
            self.assertIs(type(case["full"]), bool, case["name"])
            self.assertLessEqual(set(case), {"name", "full", "document", "drop", "set"}, case["name"])
        # the file must exercise both verdicts and every required key, or it pins nothing
        self.assertGreaterEqual(sum(case["full"] for case in self.vectors["cases"]), 20)
        self.assertGreaterEqual(sum(not case["full"] for case in self.vectors["cases"]), 100)
        dropped = {key for case in self.vectors["cases"] for key in case.get("drop", ())}
        self.assertEqual(dropped, set(dp._CEILING_REQUIRED_KEYS))
        self.assertEqual(set(self.base), set(dp._CEILING_REQUIRED_KEYS))

    def test_the_constants_are_the_recorded_definition(self) -> None:
        """The patterns, bounds, key sets and vocabularies are the ones read from the original and
        recorded in the vector file. A changed constant here fails until the file changes with it,
        and the file is written to be the bytes agent-toolkit checks its own reader against."""
        definition = self.vectors["definition"]
        self.assertEqual(set(definition), {"required_keys", "optional_keys", "authority_keys", "resident_posture",
                                           "schema_tag", "patterns", "pattern_flags", "bounds", "completion_classes",
                                           "execution_modes"})
        self.assertEqual(sorted(dp._CEILING_REQUIRED_KEYS), definition["required_keys"])
        self.assertEqual(sorted(dp._CEILING_OPTIONAL_KEYS), definition["optional_keys"])
        self.assertEqual(sorted(dp._CEILING_AUTHORITY_KEYS), definition["authority_keys"])
        self.assertEqual(dp.RESIDENT_POSTURE, definition["resident_posture"])
        self.assertEqual(dp.PROGRAMME_BLOCK_SCHEMA, definition["schema_tag"])
        self.assertEqual({"reference": dp._CEILING_REF_RE.pattern, "programme": dp._CEILING_PROGRAMME_RE.pattern,
                          "label": dp._CEILING_LABEL_RE.pattern, "hex64": dp._CEILING_HEX64_RE.pattern,
                          "scope_token": dp._CEILING_TOKEN_RE.pattern}, definition["patterns"])
        # a flag changes what a pattern admits (MULTILINE lets `$` match before any newline), so flags are pinned too
        self.assertEqual({"reference": dp._CEILING_REF_RE.flags, "programme": dp._CEILING_PROGRAMME_RE.flags,
                          "label": dp._CEILING_LABEL_RE.flags, "hex64": dp._CEILING_HEX64_RE.flags,
                          "scope_token": dp._CEILING_TOKEN_RE.flags}, definition["pattern_flags"])
        self.assertEqual(set(definition["pattern_flags"].values()), {re.compile("x").flags})  # no flag at all
        self.assertEqual({"path_envelope_max": dp.MAX_CEILING_PATH_ENVELOPE, "serial_max": dp.MAX_CEILING_SERIAL,
                          "signature_chars_max": dp.MAX_CEILING_SIGNATURE_CHARS, "active_max": dp.MAX_CEILING_ACTIVE,
                          "disjoint_max": dp.MAX_CEILING_DISJOINT, "scope_tokens_max": dp.MAX_CEILING_SCOPE_TOKENS,
                          "relpath_chars_max": dp.MAX_CEILING_RELPATH_CHARS,
                          "reference_digits_max": dp.MAX_CEILING_REF_DIGITS}, definition["bounds"])
        self.assertEqual(list(dp._CEILING_COMPLETION_CLASSES), definition["completion_classes"])
        self.assertEqual(list(dp._CEILING_EXECUTION_MODES), definition["execution_modes"])

    def test_the_judge_gives_the_pinned_verdict_for_every_vector(self) -> None:
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                self.assertIs(self.verdict(document_of(self.vectors, case)), case["full"], case["name"])

    def test_the_base_block_is_full_and_only_with_the_resident_posture(self) -> None:
        self.assertTrue(dp.is_full_resident_ceiling(copy.deepcopy(self.base)))
        self.assertEqual(self.base["posture"], dp.RESIDENT_POSTURE)
        self.assertFalse(dp.is_full_resident_ceiling(dict(self.base, posture="standing-governor-rotation")))

    def test_every_required_key_is_required_and_no_other_key_is_admitted(self) -> None:
        for key in sorted(dp._CEILING_REQUIRED_KEYS):
            with self.subTest(key):
                block = copy.deepcopy(self.base)
                del block[key]
                self.assertFalse(dp.is_full_resident_ceiling(block), key)
        self.assertFalse(dp.is_full_resident_ceiling(dict(self.base, anything="x")))
        for key in sorted(dp._CEILING_OPTIONAL_KEYS):
            with self.subTest(key):
                self.assertTrue(dp.is_full_resident_ceiling(dict(self.base, **{key: []})), key)

    def test_each_structural_guard_refuses_its_own_defect(self) -> None:
        """One defect per guard, so removing a guard is seen as exactly that guard's case."""
        defects = {
            "schema": {"schema": "standing-authority/v1"},
            "parent": {"parent": "not a reference"},
            "parent-number-python-will-not-convert": {"parent": "o/r#" + "1" * 4301},
            "parent-leading-zero": {"parent": "o/r#01"},
            "repository": {"repository": 7},
            "issue": {"issue": "3732"},
            "reference": {"repository": "no-owner"},
            "programme_id": {"programme_id": "Example"},
            "programme_id-first-character": {"programme_id": "1example"},
            "serial-type": {"serial": True},
            "serial-range": {"serial": 0},
            "not_after": {"not_after": "2000-01-01T00:00:00"},
            "posture-label": {"posture": 7},
            "digest": {"source_body_sha256": "a" * 63},
            "envelope-shape": {"path_envelope": []},
            "envelope-entry": {"path_envelope": ["../x"]},
            "envelope-duplicate": {"path_envelope": ["docs/", "docs/"]},
            "writers": {"max_active_writers": 9},
            "child-prs": {"max_active_child_prs": -1},
            "completion-class": {"granted_completion_class": "L4"},
            "execution-mode": {"execution_mode": "execute"},
            "signature-type": {"signature": None},
            "signature-length": {"signature": "A" * (dp.MAX_CEILING_SIGNATURE_CHARS + 1)},
            "disjoint-shape": {"disjoint_with": "other-seat"},
            "disjoint-self": {"disjoint_with": [self.base["programme_id"]]},
            "authority-shape": {"authority": []},
            "authority-vocabulary": {"authority": {"anything": True}},
            "authority-value": {"authority": {"repository_read": 1}},
            "scope-keys": {"scope": {"allowed": []}},
            "scope-list": {"scope": {"allowed": "docs", "forbidden": []}},
            "scope-token": {"scope": {"allowed": ["Docs"], "forbidden": []}},
            "scope-token-first-character": {"scope": {"allowed": ["1"], "forbidden": []}},
            "scope-token-charset": {"scope": {"allowed": ["docs.md"], "forbidden": []}},
            "scope-count": {"scope": {"allowed": [f"t{i}" for i in range(101)], "forbidden": []}},
        }
        for label, change in defects.items():
            with self.subTest(label):
                self.assertFalse(dp.is_full_resident_ceiling(dict(copy.deepcopy(self.base), **change)), label)

    def test_it_never_raises_whatever_it_is_given(self) -> None:
        """A verdict, never a traceback: the route treats ``False`` as "keeps its date"."""
        hostile = [None, True, 0, 1.5, "", "standing-governor-resident", [], [self.base], (), {}, {"posture": dp.RESIDENT_POSTURE},
                   float("nan")]
        for value in hostile:
            with self.subTest(repr(value)[:40]):
                self.assertIs(self.verdict(value), False)
        for key in sorted(self.base) + sorted(dp._CEILING_OPTIONAL_KEYS):
            for value in (None, True, 0, -1, 1.5, float("inf"), "", "x", [], [[]], [{}], {}, {"x": {}}, [None]):
                with self.subTest(f"{key}={value!r}"):
                    self.assertIs(type(self.verdict(dict(copy.deepcopy(self.base), **{key: value}))), bool)
        # values no pattern can be asked about and no set can hold: each is a refusal, never a raise
        for label, change in (("unhashable disjoint entry", {"disjoint_with": [["other-seat"]]}),
                              ("map as a disjoint entry", {"disjoint_with": [{"a": 1}]}),
                              ("unhashable scope token", {"scope": {"allowed": [["docs"]], "forbidden": []}}),
                              ("unhashable envelope entry", {"path_envelope": [["docs/"]]}),
                              ("map as the completion class", {"granted_completion_class": {"a": 1}})):
            with self.subTest(label):
                self.assertIs(self.verdict(dict(copy.deepcopy(self.base), **change)), False)

    def test_a_date_utc_cannot_express_is_not_a_full_ceiling(self) -> None:
        # Not a shared vector: agent-toolkit's function raises OverflowError here instead of answering.
        # The judge answers, and the answer keeps the date.
        for value in ("0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"):
            with self.subTest(value):
                self.assertIs(self.verdict(dict(self.base, not_after=value)), False)

    def test_a_reference_is_the_pattern_and_then_the_number(self) -> None:
        """The original matches the pattern and then converts the number; both halves are kept. The
        longest digit run Python converts is a reference, and one digit more is not."""
        limit = dp.MAX_CEILING_REF_DIGITS
        self.assertEqual(sys.get_int_max_str_digits(), limit)  # the written bound is the interpreter default
        self.assertIs(self.verdict(dict(self.base, parent="o/r#" + "1" * limit)), True)
        self.assertIs(self.verdict(dict(self.base, parent="o/r#" + "1" * (limit + 1))), False)
        self.assertIs(self.verdict(dict(self.base, parent="o/r#7")), True)
        for bad in ("o/r#0", "o/r#01", "o/r#", "o/r#1\n", "o/r/x#1", "o r/x#1", "#1", "o/r", "o/r#1\u0662", "\u00f6/r#1"):
            with self.subTest(bad):
                self.assertIs(self.verdict(dict(self.base, parent=bad)), False)

    def test_the_reference_bound_is_the_smaller_of_the_written_one_and_the_runner_limit(self) -> None:
        """The judge converts the number AND applies its written bound, so its limit is the smaller of
        the two. Lifting the runner's limit, from the default or from the lowest value, never admits a
        run longer than the written bound; lowering it refuses sooner. The verdict is therefore not
        independent of the runner: it is bounded above by a constant the runner cannot move."""
        bound = dp.MAX_CEILING_REF_DIGITS
        over = dict(self.base, parent="o/r#" + "1" * (bound + 1))
        at = dict(self.base, parent="o/r#" + "1" * bound)
        inside = dict(self.base, parent="o/r#" + "1" * 700)
        seen = {}
        before = sys.get_int_max_str_digits()
        try:
            for limit in (640, before, 0):  # the lowest the interpreter accepts, the default, no limit at all
                sys.set_int_max_str_digits(limit)
                seen[limit] = (self.verdict(inside), self.verdict(at), self.verdict(over))
        finally:
            sys.set_int_max_str_digits(before)
        self.assertEqual(sys.get_int_max_str_digits(), before)
        self.assertEqual(seen[640], (False, False, False))    # lowered: refuses sooner
        self.assertEqual(seen[before], (True, True, False))   # default: the written bound and the limit coincide
        self.assertEqual(seen[0], (True, True, False))        # lifted: nothing beyond the written bound

    def test_the_grant_vocabulary_is_closed_and_complete(self) -> None:
        self.assertEqual(len(dp._CEILING_AUTHORITY_KEYS), 16)
        everything = {key: False for key in dp._CEILING_AUTHORITY_KEYS}
        self.assertTrue(dp.is_full_resident_ceiling(dict(self.base, authority=everything)))
        self.assertFalse(dp.is_full_resident_ceiling(dict(self.base, authority=dict(everything, one_more=False))))


if __name__ == "__main__":
    unittest.main()
