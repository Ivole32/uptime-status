"""latency degradation: incident kind and degraded checks per day

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-29 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing incidents were all outages and no check was ever degraded, so the
    # server defaults fill in existing rows correctly.
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('kind', sa.String(length=16), server_default='down', nullable=False))
    with op.batch_alter_table('daily_stats', schema=None) as batch_op:
        batch_op.add_column(sa.Column('degraded_checks', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('degraded_ms_sum', sa.Integer(), server_default='0', nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('daily_stats', schema=None) as batch_op:
        batch_op.drop_column('degraded_ms_sum')
        batch_op.drop_column('degraded_checks')
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_column('kind')
