"""The test application's hooks: its route policy and measured fields. A test
installs others through the ``hook`` fixture."""

from mosp.security.regex import scan_pattern
from mosp.security.route_policy import PrefixRule, RouteCodes, RoutePolicy, RouteSet

ISSUED = scan_pattern(r"tst_[A-Za-z0-9]{8}")

POLICY = RoutePolicy(
    public=RouteSet({"GET": ("/health",)}),
    self_service=RouteSet(
        {method: ("/v1/me/preferences",) for method in ("PUT", "PATCH")}
    ),
    object_checked=RouteSet({"POST": ("/v1/notes/{note_id}",)}),
    gated=RouteCodes({("POST", "/v1/gated"): "gated.write"}),
    prefix_rules=(PrefixRule("/v1/reports", ("reports.run",)),),
    admin_prefixes=("/v1/admin", "/v1/users"),
    token_reads=RouteSet({"GET": ("/v1/things",)}),
    unaudited_public_reads=frozenset({"/health"}),
)


# Measured facts whose names hold a sensitive-key substring.
MEASURED = {
    "posture.password_required": "boolean",
    "posture.password_required_configured": "boolean",
    "posture.password_delay_seconds": "count",
    "posture.signatures_age_days": "count",
    "posture.signatures_updated": "timestamp",
}


def measured_fields():
    return MEASURED


def route_policy():
    return POLICY
