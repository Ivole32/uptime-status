"""legal pages: imprint and privacy policy

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-30 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('legal_pages',
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=80), nullable=True),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('kind')
    )


def downgrade() -> None:
    op.drop_table('legal_pages')
