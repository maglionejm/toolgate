from datetime import UTC, datetime

from toolgate.core import (
    AuthorizationDetail,
    Budget,
    Policy,
    ToolCallContext,
    check_budget,
    decide,
    evaluate_policy,
    glob_match,
)

POLICY = Policy(
    id="pol_1",
    tenantId="tnt_1",
    name="test policy",
    createdAt=datetime.now(UTC).isoformat(),
    rules=[
        {
            "id": "deny-bulk-delete",
            "effect": "deny",
            "match": {"upstream": "crm", "tool": "delete_*"},
        },
        {
            "id": "approve-external-email",
            "effect": "require_approval",
            "match": {
                "upstream": "email",
                "tool": "send_email",
                "where": [{"path": "to", "op": "matches", "value": "@(?!acme\\.com$)"}],
            },
        },
        {
            "id": "allow-internal-email",
            "effect": "allow",
            "match": {"upstream": "email", "tool": "send_email"},
        },
        {
            "id": "allow-crm-reads",
            "effect": "allow",
            "match": {"upstream": "crm", "tool": "*"},
            "constraints": {"maxCostUnits": 5},
        },
    ],
)

AUTHZ = [
    AuthorizationDetail(upstream="crm", tools=["*"]),
    AuthorizationDetail(upstream="email", tools=["send_email"]),
]


def call(upstream: str, tool: str, args: dict | None = None, cost: int = 1) -> ToolCallContext:
    return ToolCallContext(upstream=upstream, tool=tool, args=args or {}, cost_units=cost)


def test_default_deny():
    d = evaluate_policy(POLICY, call("billing", "charge"))
    assert d.effect == "deny" and d.source == "default"


def test_first_matching_rule_wins():
    d = evaluate_policy(POLICY, call("crm", "delete_contact"))
    assert d.effect == "deny" and d.rule_id == "deny-bulk-delete"


def test_allows_reads_under_cost_ceiling():
    d = evaluate_policy(POLICY, call("crm", "list_contacts", cost=3))
    assert d.effect == "allow" and d.rule_id == "allow-crm-reads"


def test_denies_when_cost_exceeds_ceiling():
    d = evaluate_policy(POLICY, call("crm", "export_all", cost=50))
    assert d.effect == "deny" and d.source == "constraint"


def test_arg_constraint_routes_external_email_to_approval():
    external = evaluate_policy(POLICY, call("email", "send_email", {"to": "ceo@bigcorp.com"}))
    assert external.effect == "require_approval"
    assert external.rule_id == "approve-external-email"

    internal = evaluate_policy(POLICY, call("email", "send_email", {"to": "sam@acme.com"}))
    assert internal.effect == "allow" and internal.rule_id == "allow-internal-email"


def test_token_bounds_checked_before_policy():
    d = decide(POLICY, call("email", "delete_mailbox"), AUTHZ)
    assert d.effect == "deny" and d.source == "token_bounds"


def test_permits_calls_inside_bounds_and_policy():
    d = decide(POLICY, call("crm", "read_contact"), AUTHZ)
    assert d.effect == "allow"


def test_glob_match():
    assert glob_match("*", "anything")
    assert glob_match("crm", "crm")
    assert not glob_match("crm", "crm2")
    assert glob_match("delete_*", "delete_contact")
    assert not glob_match("delete_*", "read_contact")


def test_check_budget():
    assert check_budget(Budget(maxUnits=10, spentUnits=7), 3) == check_budget(
        Budget(maxUnits=10, spentUnits=7), 3
    )
    ok = check_budget(Budget(maxUnits=10, spentUnits=7), 3)
    assert ok.ok and ok.remaining_units == 3
    broke = check_budget(Budget(maxUnits=10, spentUnits=7), 4)
    assert not broke.ok and broke.remaining_units == 3
