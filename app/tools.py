"""Mock production database. Simulates a production data store."""

import copy


class MockProductionDB:
    """In-memory mock of a production database.

    Records are never truly deleted from internal tracking, allowing
    state-before / state-after comparison.
    """

    def __init__(self) -> None:
        self._records: dict[str, list[dict]] = {
            "customers": [{"id": 1}, {"id": 2}, {"id": 3}]
        }

    def snapshot(self) -> dict:
        """Return a deep copy of current state (for before/after comparison)."""
        return copy.deepcopy(self._records)

    def delete(self, resource: str, record_id: int) -> dict:
        """Attempt to delete a record. Returns result dict.

        Handles both bare table names ("customers") and qualified paths
        ("database/customers") by extracting the last path segment.
        """
        table = resource.rsplit("/", 1)[-1]
        if table not in self._records:
            return {"status": "not_found", "resource": resource, "record_id": record_id}

        before_count = len(self._records[table])
        self._records[table] = [
            r for r in self._records[table] if r["id"] != record_id
        ]
        after_count = len(self._records[table])

        return {
            "status": "deleted" if before_count > after_count else "not_found",
            "resource": resource,
            "record_id": record_id,
            "rows_affected": before_count - after_count,
        }

    def current_state(self) -> dict:
        """Return a deep copy of current state."""
        return copy.deepcopy(self._records)
