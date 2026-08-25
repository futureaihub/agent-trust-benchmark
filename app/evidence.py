"""Hash-chained SQLite evidence store.

Each record is append-only. The entry_hash covers all fields:
  SHA-256(run_id | seq | timestamp | event_type | payload_json | prev_hash)

The chain detects modification, insertion, and reordering within the
retained chain. Tail truncation requires an externally retained
checkpoint/final anchor.

run_id binds all records in a chain to a single benchmark execution.
Cross-run contamination is rejected during chain verification.
"""

import hashlib
import json
import sqlite3
import time
import uuid

from app.schemas import EvidenceRecord


def compute_entry_hash(
    run_id: str, seq: int, timestamp: float, event_type: str, payload: dict, prev_hash: str
) -> str:
    """Compute SHA-256 over the canonical representation of a record."""
    canonical = (
        f"{run_id}|{seq}|{timestamp}|{event_type}|"
        f"{json.dumps(payload, sort_keys=True, separators=(',', ':'))}|"
        f"{prev_hash}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(
    records: list[EvidenceRecord],
) -> tuple[bool, int | None, str | None]:
    """Verify the hash chain is intact.

    Checks:
    0. Run-ID consistency: all records must share the same run_id.
    1. Sequence continuity: seq must be 0, 1, 2, ... with no gaps.
    2. Prev_hash continuity: each record's prev_hash must equal the
       previous record's entry_hash.
    3. Entry_hash correctness: recomputed hash must match stored hash.

    Returns:
        (True, None, None) if chain is valid.
        (False, seq, reason) if chain breaks at the given sequence number.
    """
    if not records:
        return True, None, None

    # Check run_id consistency
    run_ids = {r.payload.get("_run_id") for r in records}
    run_ids.discard(None)
    if len(run_ids) > 1:
        return False, 0, f"run_id_mismatch: multiple run_ids in chain: {run_ids}"
    if len(run_ids) == 0:
        return False, 0, "run_id_mismatch: no run_id found in records"

    run_id = next(iter(run_ids))
    prev_hash = ""
    expected_seq = 0

    for record in records:
        if record.seq != expected_seq:
            return (
                False,
                record.seq,
                f"sequence_gap: expected {expected_seq}, got {record.seq}",
            )

        if record.prev_hash != prev_hash:
            prev_short = prev_hash[:16] + "..." if prev_hash else "(empty)"
            got_short = record.prev_hash[:16] + "..." if record.prev_hash else "(empty)"
            return (
                False,
                record.seq,
                f"prev_hash_mismatch: expected {prev_short}, got {got_short}",
            )

        # Verify run_id is present in payload
        rec_run_id = record.payload.get("_run_id")
        if rec_run_id != run_id:
            return (
                False,
                record.seq,
                f"run_id_mismatch: record has {rec_run_id}, chain expects {run_id}",
            )

        recomputed = compute_entry_hash(
            run_id, record.seq, record.timestamp, record.event_type,
            {k: v for k, v in record.payload.items() if k != "_run_id"},
            record.prev_hash,
        )
        if record.entry_hash != recomputed:
            return False, record.seq, "entry_hash_mismatch: hash does not recompute"

        prev_hash = record.entry_hash
        expected_seq += 1

    return True, None, None


def compute_checkpoint(records: list[EvidenceRecord]) -> str:
    """Compute a simple checkpoint: SHA-256 of the last record's entry_hash.

    LIMITATION: This is computed locally. It does not prove anything unless
    retained by an external party. An attacker who controls the entire host
    can recompute after tampering. For v0.1 this is acceptable.
    """
    if not records:
        return hashlib.sha256(b"empty").hexdigest()
    last_hash = records[-1].entry_hash
    return hashlib.sha256(last_hash.encode("utf-8")).hexdigest()


class EvidenceStore:
    """Append-only, hash-chained SQLite evidence store.

    Each store is bound to a single run_id. Records from different runs
    cannot be mixed in the same chain.
    """

    def __init__(self, db_path: str = ":memory:", run_id: str | None = None):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._run_id = run_id or uuid.uuid4().hex[:16]
        self._init_db()

    @property
    def run_id(self) -> str:
        return self._run_id

    def _init_db(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                seq         INTEGER PRIMARY KEY,
                timestamp   REAL    NOT NULL,
                event_type  TEXT    NOT NULL,
                payload     TEXT    NOT NULL,
                prev_hash   TEXT    NOT NULL,
                entry_hash  TEXT    NOT NULL
            )
            """
        )
        self._conn.commit()

    def append(self, event_type: str, payload: dict) -> EvidenceRecord:
        """Append a new evidence record to the chain.

        The run_id is embedded in the payload and included in the hash.
        """
        cur = self._conn.execute("SELECT MAX(seq) FROM evidence")
        row = cur.fetchone()
        max_seq = row[0] if row[0] is not None else -1
        next_seq = max_seq + 1

        # Get prev_hash
        if next_seq == 0:
            prev_hash = ""
        else:
            cur = self._conn.execute(
                "SELECT entry_hash FROM evidence WHERE seq = ?", (next_seq - 1,)
            )
            prev_hash = cur.fetchone()["entry_hash"]

        # Embed run_id in payload for chain verification
        full_payload = {**payload, "_run_id": self._run_id}

        timestamp = time.time()
        entry_hash = compute_entry_hash(
            self._run_id, next_seq, timestamp, event_type,
            {k: v for k, v in full_payload.items() if k != "_run_id"},
            prev_hash,
        )

        self._conn.execute(
            "INSERT INTO evidence (seq, timestamp, event_type, payload, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (next_seq, timestamp, event_type, json.dumps(full_payload), prev_hash, entry_hash),
        )
        self._conn.commit()

        return EvidenceRecord(
            seq=next_seq,
            timestamp=timestamp,
            event_type=event_type,
            payload=full_payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def get_all(self) -> list[EvidenceRecord]:
        """Return all records in sequence order."""
        cur = self._conn.execute("SELECT * FROM evidence ORDER BY seq")
        rows = cur.fetchall()
        return [
            EvidenceRecord(
                seq=r["seq"],
                timestamp=r["timestamp"],
                event_type=r["event_type"],
                payload=json.loads(r["payload"]),
                prev_hash=r["prev_hash"],
                entry_hash=r["entry_hash"],
            )
            for r in rows
        ]

    def get_checkpoint_hash(self) -> str:
        """Return the checkpoint hash of the current chain."""
        return compute_checkpoint(self.get_all())

    def close(self) -> None:
        self._conn.close()
