import base64
import json
import uuid
from unittest.mock import patch

import pytest

from indexd.errors import UserError
from indexd.index.errors import NoRecordFound

ADMIN = {"Authorization": "Basic " + base64.b64encode(b"test:test").decode()}
RESOURCE = "/programs/MMRF/projects/embargoed"
SECOND = "/programs/MMRF/projects/second"


def create(client, visibility="public", authz=None, size=10):
    payload = {
        "form": "object",
        "hashes": {"md5": "a" * 32},
        "size": size,
        "urls": ["s3://test/secret.txt"],
        "authz": (
            authz
            if authz is not None
            else ([RESOURCE] if visibility == "restricted" else ["/open"])
        ),
        "file_name": "secret.txt",
        "metadata": {"sensitive": "secret"},
    }
    response = client.post("/index/", json=payload, headers=ADMIN)
    assert response.status_code == 200, response.json
    return response.json


def allow(app, resources=(RESOURCE,), service="indexd", method="read-metadata"):
    app.auth.arborist.auth_mapping.return_value = {
        "/open": [{"service": "indexd", "method": "read-metadata"}],
        **{
            resource: [{"service": service, "method": method}] for resource in resources
        },
    }


@pytest.mark.parametrize("suffix", ["", "/aliases", "/versions", "/latest"])
def test_direct_hidden_is_not_found(app, client, suffix):
    private = create(client, "restricted")
    response = client.get("/index/" + private["did"] + suffix)
    assert response.status_code == 404
    assert "secret" not in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "private, no-store"
    assert "Authorization" in response.headers["Vary"]


@pytest.mark.parametrize(
    "route",
    ["/{did}", "/ga4gh/drs/v1/objects/{did}", "/ga4gh/dos/v1/dataobjects/{did}"],
)
def test_protocol_and_global_resolvers_do_not_leak(app, client, route):
    private = create(client, "restricted")
    response = client.get(route.format(**private))
    assert response.status_code == 404
    allow(app)
    assert (
        client.get(
            route.format(**private), headers={"Authorization": "Bearer allowed"}
        ).status_code
        == 200
    )


def test_lists_filter_before_pagination_and_bulk(app, client):
    hidden = create(client, "restricted", size=99)
    public = [create(client, size=1) for _ in range(3)]
    pages = [
        client.get("/index/?limit=1&page=" + str(page)).json["records"]
        for page in range(3)
    ]
    assert {row[0]["did"] for row in pages} == {row["did"] for row in public}
    assert client.get("/index/?limit=1&page=3").json["records"] == []
    assert client.get("/index/?ids=" + hidden["did"]).json["records"] == []
    assert (
        client.post("/bulk/documents", json=[hidden["did"], public[0]["did"]]).json[0][
            "did"
        ]
        == public[0]["did"]
    )
    assert client.get("/_stats").json == {"fileCount": 3, "totalFileSize": 3}
    allow(app)
    assert client.get("/_stats", headers={"Authorization": "Bearer allowed"}).json == {
        "fileCount": 4,
        "totalFileSize": 102,
    }


def test_all_authz_resources_required_and_metadata_role_is_insufficient(app, client):
    private = create(client, "restricted", [RESOURCE, SECOND])
    allow(app, service="guppy", method="read")
    assert client.get("/index/" + private["did"]).status_code == 404
    allow(app)
    assert client.get("/index/" + private["did"]).status_code == 404
    allow(app, [RESOURCE, SECOND])
    assert client.get("/index/" + private["did"]).status_code == 200


def test_cookies_header_precedence_and_request_cache(app, client):
    private = create(client, "restricted")
    allow(app)
    client.set_cookie("access_token", "cookie-token")
    assert client.get("/index/" + private["did"]).status_code == 200
    app.auth.arborist.auth_mapping.assert_called_with(jwt="cookie-token")
    assert (
        client.get(
            "/index/" + private["did"], headers={"Authorization": "bad"}
        ).status_code
        == 404
    )
    app.auth.arborist.auth_mapping.reset_mock()
    assert client.get("/index/?limit=10").status_code == 200
    assert app.auth.arborist.auth_mapping.call_count == 1
    app.auth.arborist.auth_mapping.return_value = {}
    assert client.get("/index/" + private["did"]).status_code == 404


def test_arborist_failure_and_invalid_basic_fail_closed(app, client):
    private = create(client, "restricted")
    app.auth.arborist.auth_mapping.side_effect = RuntimeError("outage")
    assert client.get("/index/" + private["did"]).status_code == 503
    assert (
        client.get(
            "/index/" + private["did"], headers={"Authorization": "Basic dGVzdDpiYWQ="}
        ).status_code
        == 403
    )
    assert client.get("/index/" + private["did"], headers=ADMIN).status_code == 200


def test_urls_search_and_projection_cannot_bypass_visibility(app, client):
    private = create(client, "restricted")
    assert client.get("/urls/?ids=" + private["did"]).json["urls"] == []
    for fields in ["did,urls", "urls", "rev"]:
        response = client.get("/_query/urls/q?include=secret&fields=" + fields)
        assert response.status_code == 200, response.get_data(as_text=True)
        assert response.json == []
    allow(app)
    assert client.get("/_query/urls/q?include=secret&fields=urls").json == [
        {"urls": ["s3://test/secret.txt"]}
    ]


def test_aliases_and_federation_do_not_bypass_visibility(app, client):
    private = create(client, "restricted")
    assert (
        client.post(
            "/index/" + private["did"] + "/aliases/",
            json={"aliases": [{"value": "sensitive-alias"}]},
            headers=ADMIN,
        ).status_code
        == 200
    )
    assert client.get("/sensitive-alias").status_code == 404
    with patch("indexd.blueprint.dist_get_record") as resolver:
        assert client.get("/" + private["did"]).status_code == 404
        resolver.assert_not_called()
    driver = app.config["ALIAS"]["driver"]
    driver.upsert("legacy-sensitive", size=10, hashes={"md5": "a" * 32})
    assert client.get("/alias/legacy-sensitive").status_code == 404
    assert client.get("/alias/").json["aliases"] == []
    allow(app)
    assert client.get("/sensitive-alias").status_code == 200
    assert client.get("/alias/legacy-sensitive").status_code == 200


def test_version_inherits_restriction_and_cannot_clear_authz(app, client):
    private = create(client, "restricted")
    payload = {
        "form": "object",
        "hashes": {"md5": "b" * 32},
        "size": 12,
        "urls": ["s3://test/version.txt"],
    }
    response = client.post("/index/" + private["did"], json=payload, headers=ADMIN)
    assert response.status_code == 200, response.json
    new = response.json
    record = client.get("/index/" + new["did"], headers=ADMIN).json
    assert "visibility" not in record
    assert record["authz"] == [RESOURCE]
    assert client.get("/index/" + new["did"]).status_code == 404
    assert (
        client.put(
            "/index/" + new["did"] + "?rev=" + record["rev"],
            json={"authz": []},
            headers=ADMIN,
        ).status_code
        == 200
    )
    assert client.get("/index/" + new["did"]).status_code == 404
    assert (
        client.put(
            "/index/" + private["did"] + "/versions",
            json={"authz": ["/open"]},
            headers=ADMIN,
        ).status_code
        == 200
    )
    assert client.get("/index/" + new["did"]).status_code == 200


def test_bundle_snapshot_hidden_after_member_restriction(app, client):
    public = create(client)
    bundle = client.post("/bundle/", json={"bundles": [public["did"]]}, headers=ADMIN)
    assert bundle.status_code == 200, bundle.json
    identifier = bundle.json["bundle_id"]
    assert client.get("/bundle/" + identifier).status_code == 200
    assert (
        client.put(
            "/index/" + public["did"] + "?rev=" + public["rev"],
            json={"authz": [RESOURCE]},
            headers=ADMIN,
        ).status_code
        == 200
    )
    assert client.get("/bundle/" + identifier).status_code == 404
    assert client.get("/index/" + identifier).status_code == 404
    assert client.get("/bundle/").json["records"] == []
    allow(app)
    assert client.get("/bundle/" + identifier).status_code == 200


@pytest.mark.parametrize("authz", [[], ["*"], ["legacy-tag"]])
def test_restricted_requires_real_resources(app, client, authz):
    payload = {
        "form": "object",
        "hashes": {"md5": "a" * 32},
        "size": 1,
        "urls": [],
        "authz": authz,
    }
    created = client.post("/index/", json=payload, headers=ADMIN)
    assert created.status_code == 200, created.json
    assert client.get("/index/" + created.json["did"]).status_code == 404


def test_deleting_private_record_does_not_publish_historical_totals(app, client):
    private = create(client, "restricted", size=99)
    assert (
        client.delete(
            "/index/" + private["did"] + "?rev=" + private["rev"], headers=ADMIN
        ).status_code
        == 200
    )
    from indexd.index.drivers.alchemy import StatsRecord

    driver = app.config["INDEX"]["driver"]
    with driver.session as session:
        session.add(
            StatsRecord(month=1, year=2000, total_record_count=1, total_record_bytes=99)
        )
    assert client.get("/_stats?month=1&year=2000").json == {
        "fileCount": 0,
        "totalFileSize": 0,
    }


@pytest.mark.parametrize(
    "method, suffix, payload",
    [
        ("put", "?rev=wrong", {"file_name": "probe"}),
        ("delete", "?rev=wrong", None),
        (
            "post",
            "",
            {"form": "object", "hashes": {"md5": "a" * 32}, "size": 1, "urls": []},
        ),
        ("put", "/versions", {"authz": ["/open"]}),
    ],
)
def test_denied_writes_do_not_reveal_private_guid(app, client, method, suffix, payload):
    private = create(client, "restricted")
    app.auth.arborist.auth_request.return_value = False
    request = getattr(client, method)
    options = {"headers": {"Authorization": "Bearer metadata-only"}}
    if payload is not None:
        options["json"] = payload
    assert request("/index/" + private["did"] + suffix, **options).status_code == 404
    assert request("/index/" + str(uuid.uuid4()) + suffix, **options).status_code == 404


def test_download_and_discovery_permissions_are_independent(app, client):
    private = create(client, "restricted")
    allow(app, service="fence", method="read-storage")
    assert client.get("/index/" + private["did"]).status_code == 404
    allow(app, service="indexd", method="read-metadata")
    assert client.get("/index/" + private["did"]).status_code == 200
    # Discovery does not add a Fence action or change the file's data ACLs.
    assert client.get("/index/" + private["did"]).json["authz"] == [RESOURCE]
    assert app.auth.arborist.auth_mapping.return_value[RESOURCE] == [
        {"service": "indexd", "method": "read-metadata"}
    ]


def test_public_only_commons_preserves_reads_during_arborist_outage(app, client):
    public = create(client, "restricted")
    app.config["PROJECT_VISIBILITY_ENABLED"] = False
    app.auth.arborist.auth_mapping.side_effect = RuntimeError("outage")
    assert client.get("/index/" + public["did"]).status_code == 200
    assert len(client.get("/index/").json["records"]) == 1
    app.auth.arborist.auth_mapping.assert_not_called()


def test_bundle_scans_and_descendant_lookups_are_bounded(app, client):
    private = create(client, "restricted")
    for _ in range(3):
        assert (
            client.post(
                "/bundle/", json={"bundles": [private["did"]]}, headers=ADMIN
            ).status_code
            == 200
        )
    app.config["MAX_BUNDLE_VISIBILITY_ROWS"] = 2
    assert client.get("/bundle/?page=9999").status_code == 503
    # Admin pagination remains SQL-based and is unaffected by the scan budget.
    assert client.get("/bundle/?page=9999", headers=ADMIN).status_code == 200
    app.config["MAX_BUNDLE_VISIBILITY_ROWS"] = 1000
    app.config["MAX_BUNDLE_VISIBILITY_CHECKS"] = 1
    assert client.get("/bundle/").status_code == 503
