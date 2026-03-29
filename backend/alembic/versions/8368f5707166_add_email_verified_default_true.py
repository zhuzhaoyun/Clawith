"""add email_verified default true

Revision ID: 8368f5707166
Revises: add_sso_login_enabled
Create Date: 2026-03-30

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8368f5707166'
down_revision: Union[str, None] = 'add_sso_login_enabled'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add email_verified column with default True for backward compatibility
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT TRUE
    """)

    # Set existing users to verified
    op.execute("""
        UPDATE users SET email_verified = TRUE WHERE email_verified IS NULL
    """)


def downgrade() -> None:
    op.drop_column('users', 'email_verified')
