"""pola TOTP na users"""
from alembic import op
import sqlalchemy as sa


revision = "b7e4a91c2f10"
down_revision = "224cd1985849"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("totp_secret", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch_op.add_column(sa.Column("totp_last_counter", sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("totp_last_counter")
        batch_op.drop_column("totp_enabled")
        batch_op.drop_column("totp_secret")
