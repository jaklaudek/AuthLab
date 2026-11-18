"""moduł 2: blokady logowania, limity IP, canary events"""
from alembic import op
import sqlalchemy as sa


revision = "e3a1c9f07b52"
down_revision = "b7e4a91c2f10"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column("is_honeytoken", sa.Boolean(), nullable=False, server_default=sa.false())
        )

    op.create_table(
        "ip_login_attempts",
        sa.Column("ip", sa.String(length=45), primary_key=True),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "canary_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_type", sa.String(length=32), nullable=False),
        sa.Column("token_name", sa.String(length=128), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("details", sa.Text(), nullable=False, server_default=""),
    )


def downgrade():
    op.drop_table("canary_events")
    op.drop_table("ip_login_attempts")
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("is_honeytoken")
        batch_op.drop_column("locked_until")
        batch_op.drop_column("failed_login_count")
