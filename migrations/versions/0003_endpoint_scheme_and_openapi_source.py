"""endpoint: add scheme; endpoint.source: add 'openapi'

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-04

`scheme` lets a stored endpoint be turned back into a URL (`host` keeps a non-default port).
The CHECK change is written by hand: autogenerate does not compare CHECK bodies
(tests/test_migrations.py::test_check_constraints_match_enums guards against drift).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BASE = ("crawl", "fuzz", "js", "manual", "burp_paste")
_ADDED = ("openapi",)


def _replace(values: tuple[str, ...]) -> None:
    allowed = ", ".join(f"'{v}'" for v in values)
    op.drop_constraint(op.f("ck_endpoint_source"), "endpoint", type_="check")
    op.create_check_constraint(op.f("ck_endpoint_source"), "endpoint", f"source IN ({allowed})")


def upgrade() -> None:
    op.add_column(
        "endpoint", sa.Column("scheme", sa.Text(), server_default="https", nullable=False)
    )
    op.create_check_constraint(
        op.f("ck_endpoint_scheme"), "endpoint", "scheme IN ('http', 'https')"
    )
    _replace(_BASE + _ADDED)


def downgrade() -> None:
    op.execute("UPDATE endpoint SET source = 'crawl' WHERE source = 'openapi'")
    _replace(_BASE)
    op.drop_constraint(op.f("ck_endpoint_scheme"), "endpoint", type_="check")
    op.drop_column("endpoint", "scheme")
