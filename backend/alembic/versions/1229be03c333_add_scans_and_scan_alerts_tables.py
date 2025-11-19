"""add_scans_and_scan_alerts_tables

Revision ID: 1229be03c333
Revises: 4e45bd14838d
Create Date: 2025-10-16 16:04:56.672099

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '1229be03c333'
down_revision: Union[str, Sequence[str], None] = '4e45bd14838d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create ENUM types if they don't exist
    op.execute("DO $$ BEGIN CREATE TYPE scanstatus AS ENUM ('pending', 'in_progress', 'completed', 'failed', 'cancelled'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    op.execute("DO $$ BEGIN CREATE TYPE scantype AS ENUM ('basic', 'full'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    op.execute("DO $$ BEGIN CREATE TYPE risklevel AS ENUM ('high', 'medium', 'low', 'informational'); EXCEPTION WHEN duplicate_object THEN null; END $$;")

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('target_url', sa.String(), nullable=False),
        sa.Column('scan_type', sa.Enum('basic', 'full', name='scantype'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'in_progress', 'completed', 'failed', 'cancelled', name='scanstatus'), nullable=False),
        sa.Column('celery_task_id', sa.String(), nullable=True),
        sa.Column('scan_config', sa.JSON(), nullable=True),
        sa.Column('progress_percentage', sa.Integer(), nullable=False),
        sa.Column('current_step', sa.String(), nullable=True),
        sa.Column('total_alerts', sa.Integer(), nullable=False),
        sa.Column('high_risk_count', sa.Integer(), nullable=False),
        sa.Column('medium_risk_count', sa.Integer(), nullable=False),
        sa.Column('low_risk_count', sa.Integer(), nullable=False),
        sa.Column('info_count', sa.Integer(), nullable=False),
        sa.Column('error_message', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_celery_task_id'), 'scans', ['celery_task_id'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_target_url'), 'scans', ['target_url'], unique=False)
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)

    # Create scan_alerts table
    op.create_table(
        'scan_alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('alert_name', sa.String(), nullable=False),
        sa.Column('risk_level', sa.Enum('high', 'medium', 'low', 'informational', name='risklevel'), nullable=False),
        sa.Column('confidence', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('solution', sa.String(), nullable=True),
        sa.Column('reference', sa.String(), nullable=True),
        sa.Column('cwe_id', sa.String(), nullable=True),
        sa.Column('wasc_id', sa.String(), nullable=True),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('method', sa.String(), nullable=True),
        sa.Column('param', sa.String(), nullable=True),
        sa.Column('attack', sa.String(), nullable=True),
        sa.Column('evidence', sa.String(), nullable=True),
        sa.Column('other_info', sa.String(), nullable=True),
        sa.Column('alert_tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_alerts_alert_name'), 'scan_alerts', ['alert_name'], unique=False)
    op.create_index(op.f('ix_scan_alerts_risk_level'), 'scan_alerts', ['risk_level'], unique=False)
    op.create_index(op.f('ix_scan_alerts_scan_id'), 'scan_alerts', ['scan_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_scan_alerts_scan_id'), table_name='scan_alerts')
    op.drop_index(op.f('ix_scan_alerts_risk_level'), table_name='scan_alerts')
    op.drop_index(op.f('ix_scan_alerts_alert_name'), table_name='scan_alerts')
    op.drop_table('scan_alerts')

    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_index(op.f('ix_scans_target_url'), table_name='scans')
    op.drop_index(op.f('ix_scans_status'), table_name='scans')
    op.drop_index(op.f('ix_scans_celery_task_id'), table_name='scans')
    op.drop_table('scans')

    op.execute('DROP TYPE risklevel')
    op.execute('DROP TYPE scantype')
    op.execute('DROP TYPE scanstatus')
