"""remove unused columns: scan_config and verified_at

Revision ID: c8f9a2d4e1b0
Revises: b426481be371
Create Date: 2025-11-14 16:10:43.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c8f9a2d4e1b0'
down_revision: Union[str, Sequence[str], None] = 'b426481be371'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Remove unused columns from database."""
    # Remove scan_config from scans table (never used in codebase)
    op.drop_column('scans', 'scan_config')
    
    # Remove verified_at from sites table (only referenced in commented code)
    op.drop_column('sites', 'verified_at')


def downgrade() -> None:
    """Restore unused columns if needed."""
    # Restore scan_config to scans table
    op.add_column('scans', sa.Column('scan_config', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    
    # Restore verified_at to sites table
    op.add_column('sites', sa.Column('verified_at', postgresql.TIMESTAMP(), nullable=True))
