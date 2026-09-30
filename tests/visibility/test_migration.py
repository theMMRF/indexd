"""The schema upgrade preserves public defaults and refuses unsafe rollback."""

import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
import sqlalchemy as sa


@pytest.fixture
def migrated_database():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        for table in ("index_record", "record"):
            connection.execute(
                sa.text("CREATE TABLE " + table + " (id INTEGER PRIMARY KEY)")
            )
            connection.execute(sa.text("INSERT INTO " + table + " (id) VALUES (1)"))
        path = (
            Path(__file__).parents[2]
            / "migrations/versions/c47b632c18af_record_visibility.py"
        )
        spec = importlib.util.spec_from_file_location("visibility_migration", path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        yield connection, migration
    engine.dispose()


def test_upgrade_defaults_existing_rows_to_public(migrated_database):
    connection, _ = migrated_database
    for table in ("index_record", "record"):
        assert (
            connection.execute(sa.text("SELECT visibility FROM " + table)).scalar()
            == "public"
        )
    assert "record_visibility_state" in sa.inspect(connection).get_table_names()


@pytest.mark.parametrize("table", ["index_record", "record"])
def test_downgrade_refuses_restricted_rows(migrated_database, table):
    connection, migration = migrated_database
    connection.execute(sa.text("UPDATE " + table + " SET visibility = 'restricted'"))
    with pytest.raises(RuntimeError, match="Cannot downgrade"):
        migration.downgrade()
    assert "visibility" in {
        column["name"] for column in sa.inspect(connection).get_columns(table)
    }
