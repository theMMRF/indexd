import os
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, text

from indexd import get_app
from indexd.auth.drivers.alchemy import SQLAlchemyAuthDriver, Base as AuthBase
from indexd.alias.drivers.alchemy import SQLAlchemyAliasDriver, Base as AliasBase
from indexd.index.drivers.alchemy import SQLAlchemyIndexDriver, Base as IndexBase
from indexd.index.drivers.single_table_alchemy import (
    SingleTableSQLAlchemyIndexDriver,
    Base as SingleBase,
)


@pytest.fixture(params=[SQLAlchemyIndexDriver, SingleTableSQLAlchemyIndexDriver])
def app(request):
    connection = os.getenv(
        "INDEXD_VISIBILITY_TEST_DB",
        "postgresql://postgres:postgres@localhost:5432/indexd_tests",
    )
    engine = create_engine(connection)
    for base in (SingleBase, IndexBase, AliasBase, AuthBase):
        base.metadata.drop_all(engine)
    for base in (IndexBase, SingleBase, AliasBase, AuthBase):
        base.metadata.create_all(engine)
    driver = request.param(
        connection, index_config={"DEFAULT_PREFIX": "dg.MMRF/", "PREPEND_PREFIX": True}
    )
    auth = SQLAlchemyAuthDriver(connection)
    auth.add("test", "test")
    auth.arborist = MagicMock()
    auth.arborist.auth_mapping.return_value = {"/open": [{"service": "indexd", "method": "read-metadata"}]}
    app = get_app(
        {
            "AUTO_MIGRATE": False,
            "config": {
                "TESTING": True,
                "PROJECT_VISIBILITY_ENABLED": True,
                "INDEX": {"driver": driver},
                "ALIAS": {"driver": SQLAlchemyAliasDriver(connection)},
                "DIST": [],
            },
            "auth": auth,
        }
    )
    yield app
    for base in (SingleBase, IndexBase, AliasBase, AuthBase):
        base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    engine.dispose()
