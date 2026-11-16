"""push alerts through pushgate

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-16 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('monitors', schema=None) as batch_op:
        batch_op.add_column(sa.Column('alerts_enabled', sa.Boolean(), server_default='1', nullable=False))
        batch_op.add_column(sa.Column('alert_after_minutes', sa.Integer(), nullable=True))
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('alert_sent_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('recovery_sent_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_column('recovery_sent_at')
        batch_op.drop_column('alert_sent_at')
    with op.batch_alter_table('monitors', schema=None) as batch_op:
        batch_op.drop_column('alert_after_minutes')
        batch_op.drop_column('alerts_enabled')
