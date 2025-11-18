"""sync_scans_schema_with_model

Revision ID: 496feab1316f
Revises: ce3ae3d65fa2
Create Date: 2025-11-17 12:57:16.453057

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '496feab1316f'
down_revision: Union[str, Sequence[str], None] = 'ce3ae3d65fa2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
