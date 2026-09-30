"""Disposable IndexD server for real SDK and browser HTTP acceptance tests.

No production tokens or network services are used. Tokens 'allowed' and
'metadata-only' deliberately model two Arborist outcomes in this test server.
"""

import argparse
import tempfile

from werkzeug.serving import make_server

from indexd import get_app
from indexd.alias.drivers.alchemy import Base as AliasBase, SQLAlchemyAliasDriver
from indexd.auth.drivers.alchemy import Base as AuthBase, SQLAlchemyAuthDriver
from indexd.index.drivers.alchemy import Base as IndexBase, SQLAlchemyIndexDriver

RESOURCE = "/programs/MMRF/projects/private-sdk-test"


class TestArborist:
    def auth_mapping(self, jwt=""):
        if jwt == "allowed":
            return {RESOURCE: [{"service": "fence", "method": "read-storage"}]}
        return {}

    def auth_request(self, *args, **kwargs):
        return False  # No bearer writer grants in this fixture.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=58001)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="indexd-sdk-") as directory:
        database = "sqlite:///" + directory + "/indexd.db"
        driver = SQLAlchemyIndexDriver(database)
        for base in (IndexBase, AliasBase, AuthBase):
            base.metadata.create_all(driver.engine)
        auth = SQLAlchemyAuthDriver(database)
        auth.add("test", "test")
        auth.arborist = TestArborist()
        app = get_app(
            {
                "AUTO_MIGRATE": False,
                "config": {
                    "TESTING": True,
                    "INDEX": {"driver": driver},
                    "ALIAS": {"driver": SQLAlchemyAliasDriver(database)},
                    "DIST": [],
                },
                "auth": auth,
            }
        )
        with make_server("127.0.0.1", args.port, app) as server:
            print(
                "Disposable IndexD SDK fixture on localhost:" + str(args.port),
                flush=True,
            )
            server.serve_forever()


if __name__ == "__main__":
    main()
