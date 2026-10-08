"""Project visibility uses the existing authz schema and is opt-in."""

from indexd.index.drivers.alchemy import IndexRecord, Base
from indexd.index.drivers.single_table_alchemy import Record


def test_existing_database_schema_is_unchanged():
    assert "visibility" not in IndexRecord.__table__.columns
    assert "visibility" not in Record.__table__.columns
    assert "record_visibility_state" not in Base.metadata.tables


def test_opt_out_preserves_unscoped_legacy_records(app, client):
    import base64

    ADMIN = {"Authorization": "Basic " + base64.b64encode(b"test:test").decode()}
    app.config["PROJECT_VISIBILITY_ENABLED"] = False
    record = client.post(
        "/index/",
        headers=ADMIN,
        json={
            "form": "object",
            "size": 1,
            "hashes": {"md5": "a" * 32},
            "urls": [],
        },
    )
    assert record.status_code == 200
    assert client.get("/index/" + record.json["did"]).status_code == 200
    app.auth.arborist.auth_mapping.assert_not_called()
