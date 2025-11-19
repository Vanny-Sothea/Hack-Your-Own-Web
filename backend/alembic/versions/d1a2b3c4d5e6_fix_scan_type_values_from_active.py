"""drop_and_recreate_scans_tables

Revision ID: d1a2b3c4d5e6
Revises: 496feab1316f
Create Date: 2025-11-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = '496feab1316f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Drop and recreate scans and scan_alerts tables to match the current models.
    This ensures the database schema is correct with proper enum values.
    """
    # Drop existing tables (cascade will handle scan_alerts)
    op.execute("DROP TABLE IF EXISTS scan_alerts CASCADE")
    op.execute("DROP TABLE IF EXISTS scans CASCADE")
    
    # Drop existing enum types
    op.execute("DROP TYPE IF EXISTS scanstatus CASCADE")
    op.execute("DROP TYPE IF EXISTS scantype CASCADE")
    op.execute("DROP TYPE IF EXISTS risklevel CASCADE")
    
    # Create ENUM types with correct values
    op.execute("CREATE TYPE scanstatus AS ENUM ('pending', 'in_progress', 'completed', 'failed', 'cancelled')")
    op.execute("CREATE TYPE scantype AS ENUM ('basic', 'full')")
    op.execute("CREATE TYPE risklevel AS ENUM ('high', 'medium', 'low', 'informational')")
    
    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('target_url', sa.String(), nullable=False),
        sa.Column('scan_type', sa.Enum('basic', 'full', name='scantype'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'in_progress', 'completed', 'failed', 'cancelled', name='scanstatus'), nullable=False),
        sa.Column('celery_task_id', sa.String(), nullable=True),
        sa.Column('progress_percentage', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_step', sa.String(), nullable=True),
        sa.Column('total_alerts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_risk_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_risk_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_risk_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('info_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for scans table
    op.create_index(op.f('ix_scans_id'), 'scans', ['id'], unique=False)
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)
    op.create_index(op.f('ix_scans_target_url'), 'scans', ['target_url'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_celery_task_id'), 'scans', ['celery_task_id'], unique=False)
    
    # Create scan_alerts table with optimized indexes
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
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create optimized composite indexes for scan_alerts
    op.create_index(op.f('ix_scan_alerts_scan_id'), 'scan_alerts', ['scan_id'], unique=False)
    op.create_index('ix_scan_alerts_scan_risk', 'scan_alerts', ['scan_id', 'risk_level'], unique=False)
    op.create_index('ix_scan_alerts_scan_created', 'scan_alerts', ['scan_id', 'created_at'], unique=False)


def downgrade() -> None:
    """
    Downgrade by dropping the tables and enum types.
    """
    # Drop indexes
    op.drop_index('ix_scan_alerts_scan_created', table_name='scan_alerts')
    op.drop_index('ix_scan_alerts_scan_risk', table_name='scan_alerts')
    op.drop_index(op.f('ix_scan_alerts_scan_id'), table_name='scan_alerts')
    
    op.drop_index(op.f('ix_scans_celery_task_id'), table_name='scans')
    op.drop_index(op.f('ix_scans_status'), table_name='scans')
    op.drop_index(op.f('ix_scans_target_url'), table_name='scans')
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_index(op.f('ix_scans_id'), table_name='scans')
    
    # Drop tables
    op.drop_table('scan_alerts')
    op.drop_table('scans')
    
    # Drop enum types
    op.execute('DROP TYPE IF EXISTS risklevel CASCADE')
    op.execute('DROP TYPE IF EXISTS scantype CASCADE')
    op.execute('DROP TYPE IF EXISTS scanstatus CASCADE')
