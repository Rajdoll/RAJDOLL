"""scan_event.type: add 'cancelled' and 'notice'

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-04

Autogenerate does not compare CHECK constraint bodies, so this is written by hand.
tests/test_migrations.py::test_check_constraints_match_enums guards against drift.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BASE = (
    "stage_changed",
    "task_finished",
    "finding_created",
    "checkpoint_waiting",
    "paused",
    "resumed",
    "session_expired",
    "block_suspected",
    "block_sustained",
    "rate_reduced",
    "completed",
    "failed",
)
_ADDED = ("cancelled", "notice")


def _replace(values: tuple[str, ...]) -> None:
    allowed = ", ".join(f"'{v}'" for v in values)
    # op.f(): the name is final; do not apply the naming convention to it again.
    op.drop_constraint(op.f("ck_scan_event_type"), "scan_event", type_="check")
    op.create_check_constraint(op.f("ck_scan_event_type"), "scan_event", f"type IN ({allowed})")


def upgrade() -> None:
    _replace(_BASE + _ADDED)


def downgrade() -> None:
    op.execute("DELETE FROM scan_event WHERE type IN ('cancelled', 'notice')")
    _replace(_BASE)
