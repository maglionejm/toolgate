import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal

import regex

from .types import (
    ArgConstraint,
    AuthorizationDetail,
    Budget,
    DecisionEffect,
    DecisionSource,
    Policy,
    PolicyRule,
)

# `matches` runs an admin-authored regex against fully attacker-controlled
# argument values. A catastrophic pattern (e.g. "(a+)+$") plus a crafted string
# can burn CPU for seconds on the shared event loop. We evaluate these with the
# `regex` module, which enforces a wall-clock deadline mid-match, and refuse
# absurdly long inputs before we even start.
_MATCH_TIMEOUT_SECONDS = 0.1
_MATCH_MAX_INPUT = 4096


class PolicyTimeout(Exception):
    """A policy regex exceeded its evaluation budget; the caller fails closed."""


@dataclass(frozen=True)
class ToolCallContext:
    upstream: str
    tool: str
    args: dict[str, Any]
    cost_units: int


@dataclass(frozen=True)
class Decision:
    effect: DecisionEffect
    source: DecisionSource
    reason: str
    rule_id: str | None = None


def decide(
    policy: Policy,
    call: ToolCallContext,
    token_authorization: list[AuthorizationDetail],
) -> Decision:
    """Full gate decision: the token's authorization_details bound what is even
    *reachable*; policy rules then decide among reachable calls; default is
    deny. Budget is checked separately (it is stateful) via `check_budget`."""
    if not is_within_authorization(call, token_authorization):
        return Decision(
            effect="deny",
            source="token_bounds",
            reason=(
                f"tool {call.upstream}.{call.tool} is outside the token's authorization_details"
            ),
        )
    return evaluate_policy(policy, call)


def is_within_authorization(
    call: ToolCallContext, details: list[AuthorizationDetail]
) -> bool:
    return any(
        d.upstream == call.upstream and (d.tools == ["*"] or call.tool in d.tools)
        for d in details
    )


def evaluate_policy(policy: Policy, call: ToolCallContext) -> Decision:
    try:
        for index, rule in enumerate(policy.rules):
            if not _rule_matches(rule, call):
                continue
            rule_id = rule.id or f"{policy.id}#{index}"

            # A cost ceiling is a hard cap: it must deny an over-budget call
            # whether the rule would otherwise allow it OR park it for approval,
            # otherwise a `require_approval` rule silently turns the cap into an
            # approval prompt for calls the author meant to forbid outright.
            max_cost = rule.constraints.maxCostUnits if rule.constraints else None
            if (
                max_cost is not None
                and rule.effect in ("allow", "require_approval")
                and call.cost_units > max_cost
            ):
                return Decision(
                    effect="deny",
                    source="constraint",
                    rule_id=rule_id,
                    reason=f"call cost {call.cost_units} exceeds rule maxCostUnits {max_cost}",
                )

            return Decision(
                effect=rule.effect,
                source="rule",
                rule_id=rule_id,
                reason=rule.description or f"matched {rule.effect} rule {rule_id}",
            )
    except PolicyTimeout as err:
        # Fail closed: a runaway regex denies the call rather than hanging it.
        return Decision(
            effect="deny",
            source="constraint",
            reason=f"policy evaluation aborted: {err}",
        )
    return Decision(effect="deny", source="default", reason="no policy rule matched (default deny)")


def _rule_matches(rule: PolicyRule, call: ToolCallContext) -> bool:
    if rule.match.upstream is not None and not glob_match(rule.match.upstream, call.upstream):
        return False
    if rule.match.tool is not None and not glob_match(rule.match.tool, call.tool):
        return False
    if rule.match.where is not None:
        return all(constraint_holds(c, call.args) for c in rule.match.where)
    return True


@lru_cache(maxsize=512)
def _compiled_glob(pattern: str) -> re.Pattern[str]:
    return re.compile(".*".join(re.escape(part) for part in pattern.split("*")))


@lru_cache(maxsize=512)
def _compiled_search(pattern: str) -> regex.Pattern[str]:
    # `regex` (not stdlib `re`) so the match call can carry a wall-clock timeout.
    return regex.compile(pattern)


def glob_match(pattern: str, value: str) -> bool:
    """Minimal glob: "*" matches any run of characters; everything else is literal.

    Policies contain a small, stable set of patterns, so compiled regexes are
    LRU-cached — the gate evaluates these on every call.
    """
    if pattern == "*":
        return True
    return _compiled_glob(pattern).fullmatch(value) is not None


def constraint_holds(constraint: ArgConstraint, args: dict[str, Any]) -> bool:
    actual = get_path(args, constraint.path)
    expected = constraint.value
    op = constraint.op
    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op in ("gt", "gte", "lt", "lte"):
        if not _both_numbers(actual, expected):
            return False
        if op == "gt":
            return actual > expected
        if op == "gte":
            return actual >= expected
        if op == "lt":
            return actual < expected
        return actual <= expected
    if op == "in":
        return isinstance(expected, list) and actual in expected
    if op == "contains":
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        return isinstance(actual, list) and expected in actual
    if op == "startsWith":
        return (
            isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)
        )
    if op == "matches":
        if not (isinstance(actual, str) and isinstance(expected, str)):
            return False
        if len(actual) > _MATCH_MAX_INPUT:
            raise PolicyTimeout(f"argument too long to match ({len(actual)} chars)")
        try:
            return (
                _compiled_search(expected).search(actual, timeout=_MATCH_TIMEOUT_SECONDS)
                is not None
            )
        except TimeoutError as err:
            raise PolicyTimeout("regex evaluation timed out") from err
    return False


def _both_numbers(a: Any, b: Any) -> bool:
    # bool is an int subclass in Python; a numeric comparison against True/False
    # is never an intended policy, so exclude it explicitly.
    return (
        isinstance(a, (int, float))
        and not isinstance(a, bool)
        and isinstance(b, (int, float))
        and not isinstance(b, bool)
    )


def get_path(obj: dict[str, Any], path: str) -> Any:
    current: Any = obj
    for segment in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


@dataclass(frozen=True)
class BudgetCheck:
    ok: bool
    remaining_units: int


def check_budget(budget: Budget, cost_units: int) -> BudgetCheck:
    remaining = budget.maxUnits - budget.spentUnits
    return BudgetCheck(ok=cost_units <= remaining, remaining_units=remaining)


EffectLiteral = Literal["allow", "deny", "require_approval"]
