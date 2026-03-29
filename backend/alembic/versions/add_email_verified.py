"""Add email_verified column to users table.

Revision ID: add_email_verified
Revises: add_tool_source
Create Date: 2026-03-30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_email_verified'
down_revision: Union[str, None] = 'add_tool_source'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add email_verified column with default False
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE")

    # Create index for faster queries
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'ix_users_email_verified') THEN
                CREATE INDEX ix_users_email_verified ON users(email_verified);
            END IF;
        END $$;
    """)


def downgrade() -> None:
    # Drop index first
    op.execute("DROP INDEX IF EXISTS ix_users_email_verified")
    # Drop column
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS email_verified")
