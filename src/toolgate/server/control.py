import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, Field

from toolgate.core import (
    AgentIdentity,
    AuthorizationDetail,
    Budget,
    DelegationGrant,
    ErrorCodes,
    Policy,
    PolicyRule,
    Tenant,
    ToolDef,
    ToolgateError,
    Upstream,
    User,
    jwk_thumbprint,
    mint_capability_token,
    new_id,
    verify_client_assertion,
)

from .context import AppContext

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
    scopes: list[str] = []
    authorization: list[AuthorizationDetail] = Field(min_length=1)
    budgetMaxUnits: int = Field(gt=0)
    ttlHours: float = Field(default=24, gt=0)


class DecideApproval(BaseModel):
    decision: Literal["approve", "deny"]
    decidedBy: str = Field(min_length=1)


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


def control_router(ctx: AppContext) -> APIRouter:
    router = APIRouter(prefix="/v1/control")

    async def require_admin(
        x_toolgate_admin_key: Annotated[str | None, Header()] = None,
    ) -> None:
        if x_toolgate_admin_key != ctx.config.admin_key:
            raise ToolgateError(ErrorCodes.TOKEN_INVALID, "missing or wrong admin key")

    admin_dep = [Depends(require_admin)]

    @router.post("/tenants", status_code=201, dependencies=admin_dep)
    async def create_tenant(body: CreateTenant) -> Tenant:
        tenant = Tenant(id=new_id("tnt"), name=body.name, createdAt=_now())
        ctx.store.put_tenant(tenant)
        return tenant

    @router.post("/users", status_code=201, dependencies=admin_dep)
    async def create_user(body: CreateUser) -> User:
        _require_tenant(ctx, body.tenantId)
        user = User(
            id=new_id("usr"),
            tenantId=body.tenantId,
            displayName=body.displayName,
            email=body.email,
            createdAt=_now(),
        )
        ctx.store.put_user(user)
        return user

    @router.post("/agents", status_code=201, dependencies=admin_dep)
    async def create_agent(body: CreateAgent) -> AgentIdentity:
        _require_tenant(ctx, body.tenantId)
        agent = AgentIdentity(
            id=new_id("agt"),
            tenantId=body.tenantId,
            name=body.name,
            publicJwk=body.publicJwk,
            status="active",
            createdAt=_now(),
        )
        ctx.store.put_agent(agent)
        return agent

    @router.post("/upstreams", status_code=201, dependencies=admin_dep)
    async def create_upstream(body: CreateUpstream) -> Upstream:
        _require_tenant(ctx, body.tenantId)
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
        return upstream

    @router.post("/policies", status_code=201, dependencies=admin_dep)
    async def create_policy(body: CreatePolicy) -> Policy:
        _require_tenant(ctx, body.tenantId)
        policy = Policy(
            id=new_id("pol"),
            tenantId=body.tenantId,
            name=body.name,
            rules=body.rules,
            createdAt=_now(),
        )
        ctx.store.put_policy(policy)
        return policy

    @router.post("/grants", status_code=201, dependencies=admin_dep)
    async def create_grant(body: CreateGrant) -> DelegationGrant:
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
        return grant

    @router.get("/tenants", dependencies=admin_dep)
    async def list_tenants() -> list[Tenant]:
        return ctx.store.list_tenants()

    @router.get("/users", dependencies=admin_dep)
    async def list_users(tenantId: Annotated[str, Query()]) -> list[dict[str, Any]]:
        users = ctx.store.list_users(tenantId)
        return [u.model_dump(mode="json", exclude_none=True) for u in users]

    @router.get("/agents", dependencies=admin_dep)
    async def list_agents(tenantId: Annotated[str, Query()]) -> list[AgentIdentity]:
        return ctx.store.list_agents(tenantId)

    @router.get("/upstreams", dependencies=admin_dep)
    async def list_upstreams(tenantId: Annotated[str, Query()]) -> list[Upstream]:
        return ctx.store.list_upstreams(tenantId)

    @router.get("/policies", dependencies=admin_dep)
    async def list_policies(tenantId: Annotated[str, Query()]) -> list[dict[str, Any]]:
        return [
            p.model_dump(mode="json", exclude_none=True) for p in ctx.store.list_policies(tenantId)
        ]

    @router.get("/grants", dependencies=admin_dep)
    async def list_grants(tenantId: Annotated[str, Query()]) -> list[DelegationGrant]:
        return ctx.store.list_grants(tenantId)

    @router.get("/grants/{grant_id}", dependencies=admin_dep)
    async def get_grant(grant_id: str) -> DelegationGrant:
        grant = ctx.store.get_grant(grant_id)
        if not grant:
            raise _not_found("grant", grant_id)
        return grant

    @router.post("/grants/{grant_id}/revoke", dependencies=admin_dep)
    async def revoke_grant(grant_id: str) -> dict[str, str]:
        grant = ctx.store.get_grant(grant_id)
        if not grant:
            raise _not_found("grant", grant_id)
        grant.status = "revoked"
        ctx.store.put_grant(grant)
        return {"id": grant.id, "status": grant.status}

    @router.get("/approvals", dependencies=admin_dep)
    async def list_approvals(
        tenantId: Annotated[str, Query()],
        status: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, Any]]:
        approvals = ctx.store.list_approvals(tenantId, status)
        return [a.model_dump(mode="json", exclude_none=True) for a in approvals]

    @router.post("/approvals/{approval_id}/decide", dependencies=admin_dep)
    async def decide_approval(approval_id: str, body: DecideApproval) -> dict[str, Any]:
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
        approval.decidedBy = body.decidedBy
        ctx.store.put_approval(approval)
        return approval.model_dump(mode="json", exclude_none=True)

    @router.get("/audit", dependencies=admin_dep)
    async def list_audit(
        tenantId: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, Any]]:
        return [
            r.model_dump(mode="json", exclude_none=True) for r in ctx.store.list_audit(tenantId)
        ]

    @router.get("/audit/verify", dependencies=admin_dep)
    async def verify_audit() -> dict[str, Any]:
        v = ctx.audit.verify()
        out: dict[str, Any] = {"valid": v.valid, "length": v.length}
        if v.broken_at_seq is not None:
            out["broken_at_seq"] = v.broken_at_seq
            out["reason"] = v.reason
        return out

    return router


def token_router(ctx: AppContext) -> APIRouter:
    """Token endpoint (agent-facing, not admin-authed): RFC 8693-style exchange
    of a client assertion + grant reference for a capability token."""
    router = APIRouter()

    @router.post("/v1/token")
    async def exchange(body: TokenRequest) -> dict[str, Any]:
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
