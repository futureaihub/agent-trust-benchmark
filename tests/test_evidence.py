"""Unit tests for the SHA-256 evidence hash chain."""

from app.evidence import EvidenceStore, compute_entry_hash, verify_chain
from app.schemas import EvidenceRecord

TEST_RUN = "test_run_001"


class TestEvidenceChain:
    """Verify chain detection of modification, insertion, reordering, and gaps."""

    def test_empty_chain_valid(self):
        valid, seq, reason = verify_chain([])
        assert valid is True
        assert seq is None
        assert reason is None

    def test_single_record_valid(self):
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("test_event", {"key": "value"})
        valid, _, _ = verify_chain(store.get_all())
        assert valid is True

    def test_multi_record_valid(self):
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        store.append("event_b", {"y": 2})
        store.append("event_c", {"z": 3})
        valid, _, _ = verify_chain(store.get_all())
        assert valid is True

    def test_detects_payload_tampering(self):
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        store.append("event_b", {"y": 2})
        records = store.get_all()
        records[0].payload["x"] = 999
        valid, seq, reason = verify_chain(records)
        assert valid is False
        assert seq == 0
        assert "entry_hash_mismatch" in reason

    def test_detects_prev_hash_tampering(self):
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        store.append("event_b", {"y": 2})
        records = store.get_all()
        records[1].prev_hash = "0" * 64
        valid, seq, reason = verify_chain(records)
        assert valid is False
        assert seq == 1
        assert "prev_hash_mismatch" in reason

    def test_detects_entry_hash_tampering(self):
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        records = store.get_all()
        records[0].entry_hash = "a" * 64
        valid, seq, reason = verify_chain(records)
        assert valid is False
        assert seq == 0
        assert "entry_hash_mismatch" in reason

    def test_detects_sequence_gap(self):
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        records = store.get_all()
        records[0].seq = 5
        valid, seq, reason = verify_chain(records)
        assert valid is False
        assert seq == 5
        assert "sequence_gap" in reason

    def test_detects_record_insertion(self):
        """Inserting a valid fake record between two originals breaks the second's prev_hash."""
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        store.append("event_c", {"z": 3})
        records = store.get_all()

        fake = EvidenceRecord(
            seq=1,
            timestamp=0.0,
            event_type="fake",
            payload={"y": 2, "_run_id": TEST_RUN},
            prev_hash=records[0].entry_hash,
            entry_hash=compute_entry_hash(
                TEST_RUN, 1, 0.0, "fake", {"y": 2}, records[0].entry_hash
            ),
        )
        records.insert(1, fake)

        valid, seq, reason = verify_chain(records)
        assert valid is False
        assert seq == 1
        assert "sequence_gap" in reason

    def test_detects_record_deletion(self):
        """Removing a record causes the next record's prev_hash to mismatch."""
        store = EvidenceStore(":memory:", run_id=TEST_RUN)
        store.append("event_a", {"x": 1})
        store.append("event_b", {"y": 2})
        store.append("event_c", {"z": 3})
        records = store.get_all()

        records.pop(1)
        for i, r in enumerate(records):
            r.seq = i

        valid, seq, reason = verify_chain(records)
        assert valid is False
        assert seq == 1
        assert "prev_hash_mismatch" in reason

    def test_compute_entry_hash_deterministic(self):
        h1 = compute_entry_hash(TEST_RUN, 0, 1.0, "test", {"a": 1}, "")
        h2 = compute_entry_hash(TEST_RUN, 0, 1.0, "test", {"a": 1}, "")
        assert h1 == h2

    def test_compute_entry_hash_different_for_different_input(self):
        h1 = compute_entry_hash(TEST_RUN, 0, 1.0, "test", {"a": 1}, "")
        h2 = compute_entry_hash(TEST_RUN, 0, 1.0, "test", {"a": 2}, "")
        assert h1 != h2

    def test_detects_cross_run_contamination(self):
        """Records from different run_ids in the same chain are rejected."""
        store_a = EvidenceStore(":memory:", run_id="run_A")
        store_b = EvidenceStore(":memory:", run_id="run_B")
        store_a.append("event_a", {"x": 1})
        store_b.append("event_b", {"y": 2})

        # Mix records: A's record + B's record
        mixed = store_a.get_all() + store_b.get_all()
        # Renumber to look like a valid chain
        for i, r in enumerate(mixed):
            r.seq = i

        valid, seq, reason = verify_chain(mixed)
        assert valid is False
        assert "run_id_mismatch" in reason
