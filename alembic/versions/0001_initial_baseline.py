"""initial baseline (all tables, mirrors former create_all)

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-21

"""
from alembic import op

from multi_agent_system.core.db import Base
from multi_agent_system.models import models, hitl_models, ground_truth  # noqa: F401 register all tables

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # checkfirst=True (default) skips tables that already exist, so this is
    # safe to run against a DB previously created via Base.metadata.create_all().
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
