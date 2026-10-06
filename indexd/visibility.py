"""Request-scoped visibility, independent of Fence download authorization."""

from contextvars import ContextVar

from flask import current_app, g, has_request_context, request
from sqlalchemy import and_, or_, true

from indexd.errors import UserError
from indexd.index.errors import NoRecordFound


class VisibilityUnavailable(Exception):
    """Visibility could not be checked safely."""


def validate_visibility(visibility, authz):
    if visibility not in ("public", "restricted"):
        raise UserError("visibility must be public or restricted")
    if visibility == "restricted" and (
        not isinstance(authz, list)
        or not authz
        or any(
            not isinstance(resource, str) or not resource.startswith("/")
            for resource in authz
        )
    ):
        raise UserError("Restricted records require nonempty authz resource paths")


def _allows(actions, service, method):
    return any(
        action.get("service") in (service, "*")
        and action.get("method") in (method, "*")
        for action in actions
    )


def visibility_access():
    """Return (administrator, metadata-readable resources), cached only for this request.

    Background migration/indexing code keeps access to the complete database.
    Basic credentials are validated by the existing IndexD auth driver. Bearer
    tokens and cookies are validated by Arborist, never by decoding a JWT here.
    """
    if not has_request_context():
        return True, frozenset()
    cached = getattr(g, "indexd_visibility_access", None)
    if cached is not None and cached[0] is request._get_current_object():
        return cached[1]
    # A commons opts in by creating its first restricted record. Public-only
    # installations retain their unauthenticated read path, including during an
    # Arborist outage. The sticky marker also protects historical private totals.
    from indexd.index.drivers.alchemy import VisibilityState

    driver = current_app.config["INDEX"]["driver"]
    with driver.session as session:
        if session.query(VisibilityState).first() is None:
            result = True, frozenset()
            g.indexd_visibility_access = (request._get_current_object(), result)
            return result
    authorization = request.authorization
    if authorization and authorization.type == "basic":
        current_app.auth.auth(authorization.username, authorization.password)
        result = True, frozenset()
    else:
        header = request.headers.get("Authorization")
        if header is not None:
            parts = header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                result = False, frozenset()
                g.indexd_visibility_access = (request._get_current_object(), result)
                return result
            token = parts[1]
        else:
            token = request.cookies.get("access_token")
        arborist = getattr(current_app.auth, "arborist", None)
        if arborist is None:
            result = False, frozenset()
        else:
            try:
                mapping = arborist.auth_mapping(jwt=token or "")
                if not isinstance(mapping, dict) or any(
                    not isinstance(actions, list) for actions in mapping.values()
                ):
                    raise ValueError("Invalid authorization mapping")
                admin = _allows(
                    mapping.get("/services/indexd/admin", []), "indexd", "read"
                )
                resources = frozenset(
                    resource
                    for resource, actions in mapping.items()
                    if _allows(actions, "indexd", "read-metadata")
                )
                result = admin, resources
            except Exception as exc:
                if getattr(exc, "code", None) in (401, 403, 404):
                    result = False, frozenset()
                else:
                    raise VisibilityUnavailable() from exc
    g.indexd_visibility_access = (request._get_current_object(), result)
    return result


def visibility_filter(model):
    """SQL predicate applied BEFORE pagination, projection and aggregation.

    Metadata reads require indexd/read-metadata on every resource in authz.
    Storage access remains a separate Fence permission on those resources.
    """
    admin, resources = visibility_access()
    if admin:
        return true()
    public = model.visibility == "public"
    if not resources:
        return public
    if model.__tablename__ == "record":
        allowed = and_(
            model.authz != None,
            model.authz != [],
            model.authz.contained_by(list(resources)),
        )
    else:
        from indexd.index.drivers.alchemy import IndexRecordAuthz

        allowed = and_(
            model.authz.any(),
            ~model.authz.any(~IndexRecordAuthz.resource.in_(resources)),
        )
    return or_(public, and_(model.visibility == "restricted", allowed))


def authorize_private_write(record, method):
    """Mask denied mutations before revision/shape errors reveal a private GUID."""
    if record.visibility != "restricted" or not has_request_context():
        return
    from indexd import auth

    resources = (
        record.authz
        if record.__tablename__ == "record"
        else [entry.resource for entry in record.authz]
    )
    try:
        auth.authorize(method, resources)
    except Exception as exc:
        raise NoRecordFound("no record found") from exc


def mark_record_restricted(mapper, connection, record):
    """Persist privacy use in the same transaction as the record write."""
    if record.visibility == "restricted":
        from sqlalchemy import text

        connection.execute(
            text(
                "INSERT INTO record_visibility_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
            )
        )


def visible_stats(driver, model, month=None, year=None):
    import datetime
    from sqlalchemy import func
    from indexd.index.drivers.alchemy import VisibilityState, get_stats

    with driver.session as session:
        admin, _ = visibility_access()
        restricted_used = session.query(VisibilityState).first() is not None
        if admin or (
            not restricted_used
            and not session.query(model).filter(model.visibility != "public").first()
        ):
            return get_stats(session, month, year)
        query = session.query(
            func.count(), func.coalesce(func.sum(model.size), 0)
        ).filter(visibility_filter(model))
        if month is not None and year is not None:
            month, year = int(month), int(year)
            end = datetime.datetime(year + (month == 12), month % 12 + 1, 1)
            query = query.filter(model.created_date < end)
        count, size = query.one()
        return int(count), int(size)


def require_visible_bundle(driver, document):
    """Check live descendants, including unexpanded bundles and stored snapshots.

    A bundle is visible only when every referenced object is visible. Missing or
    deleted members also hide it, so historical cached metadata cannot leak.
    """

    def check(contents):
        for item in contents:
            identifier = item.get("id")
            visiting = _bundle_visiting.get()
            if not identifier or identifier in visiting:
                raise NoRecordFound("no record found")
            consume_bundle_visibility_budget()
            if len(visiting) >= 64:
                raise VisibilityUnavailable("Bundle visibility depth limit exceeded")
            context = _bundle_visiting.set(visiting | {identifier})
            try:
                driver.get_with_nonstrict_prefix(identifier)
                check(item.get("contents", []))
            finally:
                _bundle_visiting.reset(context)

    check(document.get("bundle_data", []))
    return document


_bundle_visiting = ContextVar("indexd_bundle_visiting", default=frozenset())


def legacy_alias_visible(size, hashes):
    """Legacy hash aliases must not reveal metadata associated with hidden files."""
    if not has_request_context():
        return True
    driver = current_app.config["INDEX"]["driver"]
    if driver.__class__.__name__ == "SingleTableSQLAlchemyIndexDriver":
        from indexd.index.drivers.single_table_alchemy import Record as model

        with driver.session as session:
            query = session.query(model).filter(
                ~visibility_filter(model), model.size == size
            )
            for key, value in hashes.items():
                query = query.filter(model.hashes.contains({key: value}))
            return query.first() is None
    from indexd.index.drivers.alchemy import IndexRecord, IndexRecordHash

    with driver.session as session:
        query = session.query(IndexRecord).filter(
            ~visibility_filter(IndexRecord), IndexRecord.size == size
        )
        for key, value in hashes.items():
            query = query.filter(
                IndexRecord.hashes.any(
                    and_(
                        IndexRecordHash.hash_type == key,
                        IndexRecordHash.hash_value == value,
                    )
                )
            )
        return query.first() is None


def consume_bundle_visibility_budget():
    """Bound descendant lookups across all bundles in a single HTTP request."""
    if not has_request_context():
        return
    current = request._get_current_object()
    cached = getattr(g, "indexd_bundle_checks", None)
    count = cached[1] if cached is not None and cached[0] is current else 0
    count += 1
    if count > current_app.config.get("MAX_BUNDLE_VISIBILITY_CHECKS", 5000):
        raise VisibilityUnavailable("Bundle visibility lookup limit exceeded")
    g.indexd_bundle_checks = current, count
