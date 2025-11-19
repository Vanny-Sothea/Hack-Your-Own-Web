"""merge_scan_and_site_migrations

Revision ID: b37ca55f8b1b
Revises: 1229be03c333, 70c0a6dde6e5
Create Date: 2025-10-20 18:00:47.703197

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'b37ca55f8b1b'
down_revision: Union[str, Sequence[str], None] = ('1229be03c333', '70c0a6dde6e5')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
