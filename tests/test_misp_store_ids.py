"""Tests for sequential id allocation (C-2).

Covers the scan-and-allocate logic that create_pir/gir/rfi run while holding
_id_lock. The lock placement itself is verified by reading the create
functions; here we pin the allocation/reuse semantics.

    python -m unittest tests.test_misp_store_ids
"""

import unittest

from webapp import misp_store


class FakeMisp:
    def __init__(self, infos):
        self._infos = infos

    def search(self, **kwargs):
        return [type("E", (), {"info": i})() for i in self._infos]


class SequenceId(unittest.TestCase):
    def test_scan_returns_highest_number(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-001", "[zsazsa:pir] PIR-007: q", "noise"])
        self.assertEqual(misp_store._scan_max_sequence(misp, "tag", "PIR"), 7)

    def test_scan_empty_store_is_zero(self):
        self.assertEqual(misp_store._scan_max_sequence(FakeMisp([]), "tag", "PIR"), 0)

    def test_scan_ignores_malformed_numbers(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-abc", "[zsazsa:pir] PIR-003"])
        self.assertEqual(misp_store._scan_max_sequence(misp, "tag", "PIR"), 3)

    def test_allocate_next_when_blank(self):
        misp = FakeMisp(["[zsazsa:rfi] RFI-004"])
        self.assertEqual(misp_store._sequence_id(misp, "tag", "RFI", ""), "RFI-005")

    def test_first_id_on_empty_store(self):
        self.assertEqual(misp_store._sequence_id(FakeMisp([]), "tag", "GIR", ""), "GIR-001")

    def test_existing_id_is_reused_not_reallocated(self):
        # Recreate path: an explicit id must be kept as-is.
        misp = FakeMisp(["[zsazsa:pir] PIR-009"])
        self.assertEqual(misp_store._sequence_id(misp, "tag", "PIR", "PIR-002"), "PIR-002")

    def test_whitespace_only_id_is_treated_as_blank(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-009"])
        self.assertEqual(misp_store._sequence_id(misp, "tag", "PIR", "   "), "PIR-010")


if __name__ == "__main__":
    unittest.main()
