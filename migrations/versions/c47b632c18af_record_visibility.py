"""Opt-in record visibility; existing records retain public metadata.

Revision ID: c47b632c18af
Revises: 9a2169051163
"""

from alembic import op
import sqlalchemy as sa

revision = "c47b632c18af"
down_revision = "9a2169051163"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "record_visibility_state", sa.Column("id", sa.Integer(), primary_key=True)
    )
    for table in ("index_record", "record"):
        op.add_column(
            table,
            sa.Column(
                "visibility", sa.String(), nullable=False, server_default="public"
            ),
        )
        op.create_index("ix_" + table + "_visibility", table, ["visibility"])


def downgrade():
    # Dropping visibility would silently publish restricted metadata.
    connection = op.get_bind()
    for table in ("index_record", "record"):
        if connection.execute(
            sa.text("SELECT 1 FROM " + table + " WHERE visibility != 'public' LIMIT 1")
        ).first():
            raise RuntimeError("Cannot downgrade while restricted records exist")
    op.drop_table("record_visibility_state")
    for table in ("index_record", "record"):
        op.drop_index("ix_" + table + "_visibility", table_name=table)
        op.drop_column(table, "visibility")
