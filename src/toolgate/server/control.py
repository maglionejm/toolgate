import hashlib
import hmac
import ipaddress
import secrets as _secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field

from toolgate.core import (
    AgentIdentity,
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    AuthorizationDetail,
    Budget,
    DelegationGrant,
    ErrorCodes,
    Operator,
    Policy,
    PolicyRule,
    Tenant,
    ToolCallContext,
    ToolDef,
    ToolgateError,
    Upstream,
    User,
    decide,
    evaluate_policy,
    hash_args,
    jwk_thumbprint,
    mint_capability_token,
    new_id,
    validate_public_ed25519_jwk,
    verify_client_assertion,
)

from .context import AppContext

# Cloud instance-metadata endpoints are never a legitimate upstream; they are
# the classic SSRF credential-exfiltration target, so they are refused outright.
_BLOCKED_UPSTREAM_HOSTS = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"}
)


def _validate_upstream_base_url(base_url: str, *, allow_insecure: bool) -> None:
    """Reject upstream base URLs that would leak the injected credential.

    The gate POSTs the real upstream secret to this URL, so `http://` sends it
    in cleartext — allowed only for loopback dev, or when the operator has
    explicitly opted in. Toolgate upstreams are *meant* to be internal services,
    so private ranges are NOT blocked; only cloud metadata endpoints are.
    """
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise ToolgateError(
            ErrorCodes.VALIDATION, f"upstream baseUrl scheme must be http(s), got {parts.scheme!r}"
        )
    host = (parts.hostname or "").lower()
    if not host:
        raise ToolgateError(ErrorCodes.VALIDATION, "upstream baseUrl must include a host")
    if host in _BLOCKED_UPSTREAM_HOSTS:
        raise ToolgateError(
            ErrorCodes.VALIDATION, "upstream baseUrl targets a blocked metadata host"
        )
    if parts.scheme == "http":
        is_loopback = host in ("localhost", "127.0.0.1", "::1")
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not (is_loopback or allow_insecure):
            raise ToolgateError(
                ErrorCodes.VALIDATION,
                "upstream baseUrl must use https (cleartext credential would leak); "
                "http is allowed only for loopback or with TOOLGATE_DEV set",
            )

# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class CreateTenant(BaseModel):
    name: str = Field(min_length=1)


class CreateUser(BaseModel):
    tenantId: str
    displayName: str = Field(min_length=1)
    email: str | None = None


class CreateAgent(BaseModel):
    tenantId: str
    name: str = Field(min_length=1)
    publicJwk: dict[str, Any]


class CredentialInput(BaseModel):
    mode: Literal["bearer", "header", "query"]
    secret: str = Field(min_length=1)
    headerName: str | None = None
    paramName: str | None = None


class CreateUpstream(BaseModel):
    tenantId: str
    name: str = Field(min_length=1)
    baseUrl: str
    credential: CredentialInput
    tools: list[ToolDef] = Field(min_length=1)


class CreatePolicy(BaseModel):
    tenantId: str
    name: str = Field(min_length=1)
    rules: list[PolicyRule]


class CreateGrant(BaseModel):
    tenantId: str
    userId: str
    agentId: str
    policyId: str
    scopes: list[str] = Field(default_factory=list)
    authorization: list[AuthorizationDetail] = Field(min_length=1)
    budgetMaxUnits: int = Field(gt=0)
    ttlHours: float = Field(default=24, gt=0)


class DecideApproval(BaseModel):
    decision: Literal["approve", "deny"]
    # Defaults to the authenticated operator; explicit override stays possible
    # for integrations that act on behalf of a named user.
    decidedBy: str | None = None


class CreateOperator(BaseModel):
    name: str = Field(min_length=1)
    role: Literal["owner", "approver", "auditor"]


class SimulateCall(BaseModel):
    upstream: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    costUnits: int = Field(default=1, ge=0)
    tainted: bool = False
    authorization: list[AuthorizationDetail] | None = None


class RotateKeys(BaseModel):
    plane: Literal["control", "gate"]


class TokenRequest(BaseModel):
    grant_type: Literal["urn:ietf:params:oauth:grant-type:token-exchange"]
    client_assertion: str = Field(min_length=1)
    grant_id: str = Field(min_length=1)
    requested_ttl_seconds: int | None = Field(default=None, gt=0)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _not_found(kind: str, entity_id: str) -> ToolgateError:
    return ToolgateError(ErrorCodes.NOT_FOUND, f"{kind} not found: {entity_id}")


def _require_tenant(ctx: AppContext, tenant_id: str) -> None:
    if not ctx.store.get_tenant(tenant_id):
        raise _not_found("tenant", tenant_id)


_ROLE_RANK = {"auditor": 0, "approver": 1, "owner": 2}


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    role: str


def control_router(ctx: AppContext) -> APIRouter:
    router = APIRouter(prefix="/v1/control")

    def _resolve_principal(
        operator_key: str | None, admin_key: str | None
    ) -> Principal:
        if operator_key:
            digest = hashlib.sha256(operator_key.encode()).hexdigest()
            op = ctx.store.find_operator_by_key_hash(digest)
            if op is None or op.status != "active":
                raise ToolgateError(ErrorCodes.TOKEN_INVALID, "unknown or disabled operator key")
            return Principal(id=op.id, name=op.name, role=op.role)
        # Constant-time compare so the most sensitive credential in the system
        # is not subject to byte-by-byte timing discrimination. The static admin
        # key is the audited break-glass path, not the daily driver.
        if admin_key is not None and hmac.compare_digest(admin_key, ctx.config.admin_key):
            return Principal(id="op_breakglass", name="break-glass admin key", role="owner")
        raise ToolgateError(ErrorCodes.TOKEN_INVALID, "missing or wrong operator/admin key")

    def require_role(min_role: str) -> list[Any]:
        async def dep(
            request: Request,
            x_toolgate_operator_key: Annotated[str | None, Header()] = None,
            x_toolgate_admin_key: Annotated[str | None, Header()] = None,
        ) -> None:
            principal = _resolve_principal(x_toolgate_operator_key, x_toolgate_admin_key)
            if _ROLE_RANK[principal.role] < _ROLE_RANK[min_role]:
                raise ToolgateError(
                    ErrorCodes.DENIED,
                    f"role {principal.role} cannot perform {min_role}-level operations",
                )
            request.state.principal = principal

        return [Depends(dep)]

    owner_dep = require_role("owner")
    approver_dep = require_role("approver")
    auditor_dep = require_role("auditor")

    def _ops_audit(
        request: Request, operation: str, payload: dict[str, Any], tenant_id: str = "-"
    ) -> None:
        """Control-plane mutations land in the same signed chain as gate calls,
        attributed to the operator who performed them."""
        principal: Principal = request.state.principal
        ctx.audit.record(
            AuditRecordInput(
                id=new_id("evt"),
                tenantId=tenant_id,
                ts=_now(),
                actor=AuditActor(
                    agentId="control-plane",
                    userId=principal.id,
                    grantId="-",
                    tokenJti="-",
                ),
                action=AuditAction(
                    callId=new_id("call"),
                    upstream="control",
                    tool=operation,
                    argsHash=hash_args(payload),
                ),
                decision=AuditDecision(
                    effect="allow",
                    source="operator",
                    reason=f"{operation} by {principal.name} ({principal.id})",
                ),
                result=AuditResult(status="executed"),
            )
        )

    @router.post("/tenants", status_code=201, dependencies=owner_dep)
    async def create_tenant(body: CreateTenant, request: Request) -> Tenant:
        tenant = Tenant(id=new_id("tnt"), name=body.name, createdAt=_now())
        ctx.store.put_tenant(tenant)
        _ops_audit(request, "tenants.create", {"id": tenant.id}, tenant.id)
        return tenant

    @router.post("/users", status_code=201, dependencies=owner_dep)
    async def create_user(body: CreateUser, request: Request) -> User:
        _require_tenant(ctx, body.tenantId)
        user = User(
            id=new_id("usr"),
            tenantId=body.tenantId,
            displayName=body.displayName,
            email=body.email,
            createdAt=_now(),
        )
        ctx.store.put_user(user)
        _ops_audit(request, "users.create", {"id": user.id}, body.tenantId)
        return user

    @router.post("/agents", status_code=201, dependencies=owner_dep)
    async def create_agent(body: CreateAgent, request: Request) -> AgentIdentity:
        _require_tenant(ctx, body.tenantId)
        # The agent proves possession of one Ed25519 private key. Reject anything
        # else here so a symmetric/other key can never be stored and later used
        # to forge assertions and PoP proofs (sender-binding collapse).
        try:
            validate_public_ed25519_jwk(body.publicJwk)
        except ValueError as err:
            raise ToolgateError(ErrorCodes.VALIDATION, f"invalid agent public key: {err}") from err
        agent = AgentIdentity(
            id=new_id("agt"),
            tenantId=body.tenantId,
            name=body.name,
            publicJwk=body.publicJwk,
            status="active",
            createdAt=_now(),
        )
        ctx.store.put_agent(agent)
        _ops_audit(
            request, "agents.register", {"id": agent.id, "jkt": agent.publicJwk.get("kid")},
            body.tenantId,
        )
        return agent

    @router.post("/upstreams", status_code=201, dependencies=owner_dep)
    async def create_upstream(body: CreateUpstream, request: Request) -> Upstream:
        _require_tenant(ctx, body.tenantId)
        _validate_upstream_base_url(
            body.baseUrl, allow_insecure=ctx.config.allow_insecure_upstreams
        )
        cred = body.credential
        if cred.mode == "header" and not cred.headerName:
            raise ToolgateError(ErrorCodes.VALIDATION, "headerName required for header mode")
        if cred.mode == "query" and not cred.paramName:
            raise ToolgateError(ErrorCodes.VALIDATION, "paramName required for query mode")

        upstream_id = new_id("ups")
        secret_ref = f"sec_{upstream_id}"
        ctx.store.put_secret(secret_ref, ctx.vault.seal(cred.secret))

        injection: dict[str, Any] = {"mode": cred.mode, "secretRef": secret_ref}
        if cred.mode == "header":
            injection["headerName"] = cred.headerName
        if cred.mode == "query":
            injection["paramName"] = cred.paramName

        upstream = Upstream(
            id=upstream_id,
            tenantId=body.tenantId,
            name=body.name,
            baseUrl=body.baseUrl,
            credential=injection,
            tools=body.tools,
            createdAt=_now(),
        )
        ctx.store.put_upstream(upstream)
        _ops_audit(request, "upstreams.add", {"id": upstream.id, "name": body.name}, body.tenantId)
        return upstream

    @router.post("/policies", status_code=201, dependencies=owner_dep)
    async def create_policy(body: CreatePolicy, request: Request) -> Policy:
        _require_tenant(ctx, body.tenantId)
        policy = Policy(
            id=new_id("pol"),
            tenantId=body.tenantId,
            name=body.name,
            rules=body.rules,
            createdAt=_now(),
        )
        ctx.store.put_policy(policy)
        _ops_audit(request, "policies.create", {"id": policy.id}, body.tenantId)
        return policy

    @router.post("/grants", status_code=201, dependencies=owner_dep)
    async def create_grant(body: CreateGrant, request: Request) -> DelegationGrant:
        _require_tenant(ctx, body.tenantId)
        if not ctx.store.get_user(body.userId):
            raise _not_found("user", body.userId)
        if not ctx.store.get_agent(body.agentId):
            raise _not_found("agent", body.agentId)
        if not ctx.store.get_policy(body.policyId):
            raise _not_found("policy", body.policyId)
        grant = DelegationGrant(
            id=new_id("grt"),
            tenantId=body.tenantId,
            userId=body.userId,
            agentId=body.agentId,
            policyId=body.policyId,
            scopes=body.scopes,
            authorization=body.authorization,
            budget=Budget(maxUnits=body.budgetMaxUnits, spentUnits=0),
            expiresAt=(datetime.now(UTC) + timedelta(hours=body.ttlHours)).isoformat(),
            status="active",
            createdAt=_now(),
        )
        ctx.store.put_grant(grant)
        _ops_audit(
            request,
            "grants.create",
            {"id": grant.id, "agent": body.agentId, "budget": body.budgetMaxUnits},
            body.tenantId,
        )
        return grant

    @router.get("/tenants", dependencies=auditor_dep)
    async def list_tenants() -> list[Tenant]:
        return ctx.store.list_tenants()

    @router.get("/users", dependencies=auditor_dep)
    async def list_users(tenantId: Annotated[str, Query()]) -> list[dict[str, Any]]:
        users = ctx.store.list_users(tenantId)
        return [u.model_dump(mode="json", exclude_none=True) for u in users]

    @router.get("/agents", dependencies=auditor_dep)
    async def list_agents(tenantId: Annotated[str, Query()]) -> list[AgentIdentity]:
        return ctx.store.list_agents(tenantId)

    @router.get("/upstreams", dependencies=auditor_dep)
    async def list_upstreams(tenantId: Annotated[str, Query()]) -> list[Upstream]:
        return ctx.store.list_upstreams(tenantId)

    @router.get("/policies", dependencies=auditor_dep)
    async def list_policies(tenantId: Annotated[str, Query()]) -> list[dict[str, Any]]:
        return [
            p.model_dump(mode="json", exclude_none=True) for p in ctx.store.list_policies(tenantId)
        ]

    @router.get("/grants", dependencies=auditor_dep)
    async def list_grants(tenantId: Annotated[str, Query()]) -> list[DelegationGrant]:
        return ctx.store.list_grants(tenantId)

    @router.get("/grants/{grant_id}", dependencies=auditor_dep)
    async def get_grant(grant_id: str) -> DelegationGrant:
        grant = ctx.store.get_grant(grant_id)
        if not grant:
            raise _not_found("grant", grant_id)
        return grant

    @router.post("/grants/{grant_id}/revoke", dependencies=owner_dep)
    async def revoke_grant(grant_id: str, request: Request) -> dict[str, str]:
        grant = ctx.store.get_grant(grant_id)
        if not grant:
            raise _not_found("grant", grant_id)
        grant.status = "revoked"
        ctx.store.put_grant(grant)
        _ops_audit(request, "grants.revoke", {"id": grant.id}, grant.tenantId)
        return {"id": grant.id, "status": grant.status}

    @router.get("/approvals", dependencies=auditor_dep)
    async def list_approvals(
        tenantId: Annotated[str, Query()],
        status: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, Any]]:
        approvals = ctx.store.list_approvals(tenantId, status)
        return [a.model_dump(mode="json", exclude_none=True) for a in approvals]

    @router.post("/approvals/{approval_id}/decide", dependencies=approver_dep)
    async def decide_approval(
        approval_id: str, body: DecideApproval, request: Request
    ) -> dict[str, Any]:
        approval = ctx.store.get_approval(approval_id)
        if not approval:
            raise _not_found("approval", approval_id)
        if approval.status != "pending":
            raise ToolgateError(
                ErrorCodes.VALIDATION, f"approval is {approval.status}, not pending"
            )
        if datetime.fromisoformat(approval.expiresAt) < datetime.now(UTC):
            approval.status = "expired"
            ctx.store.put_approval(approval)
            raise ToolgateError(ErrorCodes.VALIDATION, "approval expired")
        approval.status = "approved" if body.decision == "approve" else "denied"
        approval.decidedAt = _now()
        approval.decidedBy = body.decidedBy or request.state.principal.id
        ctx.store.put_approval(approval)
        _ops_audit(
            request,
            f"approvals.{body.decision}",
            {"id": approval.id, "tool": f"{approval.upstream}.{approval.tool}",
             "argsHash": hash_args(approval.args)},
            approval.tenantId,
        )
        return approval.model_dump(mode="json", exclude_none=True)

    @router.get("/audit", dependencies=auditor_dep)
    async def list_audit(
        tenantId: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, Any]]:
        return [
            r.model_dump(mode="json", exclude_none=True) for r in ctx.store.list_audit(tenantId)
        ]

    @router.post("/keys/rotate", dependencies=owner_dep)
    async def rotate_keys(body: RotateKeys, request: Request) -> dict[str, Any]:
        principal: Principal = request.state.principal
        if body.plane == "control":
            new = ctx.rotate_control_key()
            _ops_audit(request, "keys.rotate.control", {"kid": new.kid})
        else:
            # Gate rotation writes its own signed handoff record.
            new = ctx.rotate_gate_key(rotated_by=principal.id)
        return {"plane": body.plane, "kid": new.kid}

    @router.post("/audit/checkpoint", dependencies=owner_dep)
    async def cut_checkpoint() -> dict[str, Any]:
        cp = ctx.audit.checkpoint()
        return cp.model_dump(mode="json", exclude_none=True)

    @router.get("/audit/checkpoints", dependencies=auditor_dep)
    async def list_checkpoints() -> list[dict[str, Any]]:
        return [
            c.model_dump(mode="json", exclude_none=True) for c in ctx.store.list_checkpoints()
        ]

    @router.get("/audit/bundle", dependencies=auditor_dep)
    async def audit_bundle(
        tenantId: Annotated[str | None, Query()] = None,
    ) -> dict[str, Any]:
        """Records + checkpoints in one export. Offline verification needs the
        FULL chain, so tenant filtering applies to `records` only when asked —
        the default export is complete."""
        return {
            "records": [
                r.model_dump(mode="json", exclude_none=True)
                for r in ctx.store.list_audit(tenantId)
            ],
            "checkpoints": [
                c.model_dump(mode="json", exclude_none=True)
                for c in ctx.store.list_checkpoints()
            ],
        }

    @router.get("/audit/verify", dependencies=auditor_dep)
    async def verify_audit() -> dict[str, Any]:
        v = ctx.audit.verify()
        cp_valid, cp_total = ctx.audit.verify_checkpoints()
        out: dict[str, Any] = {
            "valid": v.valid,
            "length": v.length,
            "checkpoints_valid": cp_valid,
            "checkpoints_total": cp_total,
        }
        if v.broken_at_seq is not None:
            out["broken_at_seq"] = v.broken_at_seq
            out["reason"] = v.reason
        return out

    @router.post("/operators", status_code=201, dependencies=owner_dep)
    async def create_operator(body: CreateOperator, request: Request) -> dict[str, Any]:
        key = f"opk_{_secrets.token_urlsafe(24)}"
        operator = Operator(
            id=new_id("evt").replace("evt_", "op_"),
            name=body.name,
            role=body.role,
            keyHash=hashlib.sha256(key.encode()).hexdigest(),
            status="active",
            createdAt=_now(),
        )
        ctx.store.put_operator(operator)
        _ops_audit(request, "operators.create", {"id": operator.id, "role": operator.role})
        # The plaintext key is shown exactly once; only its hash is stored.
        return {
            "operator": operator.model_dump(mode="json", exclude={"keyHash"}),
            "key": key,
        }

    @router.get("/operators", dependencies=auditor_dep)
    async def list_operators() -> list[dict[str, Any]]:
        return [
            o.model_dump(mode="json", exclude={"keyHash"}) for o in ctx.store.list_operators()
        ]

    @router.post("/operators/{operator_id}/disable", dependencies=owner_dep)
    async def disable_operator(operator_id: str, request: Request) -> dict[str, str]:
        operator = ctx.store.get_operator(operator_id)
        if not operator:
            raise _not_found("operator", operator_id)
        operator.status = "disabled"
        ctx.store.put_operator(operator)
        _ops_audit(request, "operators.disable", {"id": operator.id})
        return {"id": operator.id, "status": operator.status}

    @router.post("/policies/{policy_id}/simulate", dependencies=auditor_dep)
    async def simulate_policy(policy_id: str, body: SimulateCall) -> dict[str, Any]:
        """Dry-run a call against a policy — no execution, no audit, no budget.
        The console's rule editor uses this to answer "would this pass?"."""
        policy = ctx.store.get_policy(policy_id)
        if not policy:
            raise _not_found("policy", policy_id)
        call = ToolCallContext(
            upstream=body.upstream,
            tool=body.tool,
            args=body.args,
            cost_units=body.costUnits,
            tainted=body.tainted,
        )
        if body.authorization is not None:
            decision = decide(policy, call, body.authorization)
        else:
            decision = evaluate_policy(policy, call)
        return {
            "effect": decision.effect,
            "source": decision.source,
            "ruleId": decision.rule_id,
            "reason": decision.reason,
        }

    return router


def token_router(ctx: AppContext) -> APIRouter:
    """Token endpoint (agent-facing, not admin-authed): RFC 8693-style exchange
    of a client assertion + grant reference for a capability token."""
    router = APIRouter()

    @router.post("/v1/token")
    async def exchange(body: TokenRequest) -> dict[str, Any]:
        if not ctx.token_limiter.allow(body.grant_id):
            raise ToolgateError(
                ErrorCodes.RATE_LIMITED, "token exchange rate limit exceeded for this grant"
            )
        grant = ctx.store.get_grant(body.grant_id)
        if not grant:
            raise ToolgateError(ErrorCodes.NOT_FOUND, "unknown grant")
        if grant.status != "active":
            raise ToolgateError(ErrorCodes.REVOKED, "grant revoked")
        if datetime.fromisoformat(grant.expiresAt) < datetime.now(UTC):
            raise ToolgateError(ErrorCodes.TOKEN_EXPIRED, "grant expired")

        agent = ctx.store.get_agent(grant.agentId)
        if not agent or agent.status != "active":
            raise ToolgateError(ErrorCodes.REVOKED, "agent unknown or disabled")

        token_url = f"{ctx.config.issuer}/v1/token"
        assertion = verify_client_assertion(
            agent.publicJwk, body.client_assertion, expected_audience=token_url
        )
        if assertion.agent_id != grant.agentId:
            raise ToolgateError(ErrorCodes.TOKEN_INVALID, "assertion is not from the granted agent")
        if not ctx.store.consume_jti(assertion.jti, "assertion", 300):
            raise ToolgateError(ErrorCodes.TOKEN_INVALID, "client assertion replayed")

        ttl = min(
            body.requested_ttl_seconds or ctx.config.token_ttl_seconds,
            ctx.config.max_token_ttl_seconds,
        )
        minted = mint_capability_token(
            ctx.control_signing_jwk,
            issuer=ctx.config.issuer,
            audience=ctx.config.gate_audience,
            tenant_id=grant.tenantId,
            user_id=grant.userId,
            agent_id=grant.agentId,
            grant_id=grant.id,
            scopes=grant.scopes,
            authorization_details=grant.authorization,
            agent_jkt=jwk_thumbprint(agent.publicJwk),
            ttl_seconds=ttl,
        )
        return {
            "access_token": minted.token,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": max(1, round(minted.expires_at.timestamp() - time.time())),
            "jti": minted.jti,
            "txn": minted.txn,
        }

    return router
