"""merge heads

Revision ID: ce3ae3d65fa2
Revises: 6336603e94cd, c8f9a2d4e1b0
Create Date: 2025-11-14 16:12:42.449946

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'ce3ae3d65fa2'
down_revision: Union[str, Sequence[str], None] = ('6336603e94cd', 'c8f9a2d4e1b0')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
