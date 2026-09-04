"""Domain models. Field names are camelCase on purpose: they are the wire and
storage format, kept identical to the original TypeScript implementation so
documents, audit chains, and API clients survive the language port."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Tool + upstream registry
# ---------------------------------------------------------------------------


class ToolDef(BaseModel):
    name: str = Field(min_length=1)
    description: str | None = None
    # Side-effecting tools are the ones worth gating hardest (writes, sends, payments).
    sideEffecting: bool = False
    # Abstract cost of one invocation, charged against the grant budget.
    costUnits: int = Field(default=1, ge=0)
    # Tools that return attacker-influenced content (web pages, inbound email)
    # taint the task; policies can then gate side effects in tainted tasks.
    contentTrust: Literal["trusted", "untrusted_source"] = "trusted"
    # Optional JSON Schema for the tool arguments (surfaced to MCP clients and
    # framework adapters; not enforced by the gate).
    argsSchema: dict[str, Any] | None = None


class BearerCredential(BaseModel):
    mode: Literal["bearer"]
    secretRef: str


class HeaderCredential(BaseModel):
    mode: Literal["header"]
    headerName: str
    secretRef: str


class QueryCredential(BaseModel):
    mode: Literal["query"]
    paramName: str
    secretRef: str


class OAuthUserCredential(BaseModel):
    """Per-user third-party credential (#11): at call time the gate resolves
    the OAuth connection belonging to the grant's userId and injects that
    user's live access token — agents act with Sam's connection, never a
    tenant-wide secret, and never see the token."""

    mode: Literal["oauth_user"]
    providerAppId: str = Field(min_length=1)


# How the gate injects the real credential into the upstream request.
# The secret itself lives in the vault under `secretRef` — never in this object.
CredentialInjection = Annotated[
    BearerCredential | HeaderCredential | QueryCredential | OAuthUserCredential,
    Field(discriminator="mode"),
]


class Upstream(BaseModel):
    id: str
    tenantId: str
    # Stable name used in tokens/policies, e.g. "crm" or "email".
    name: str = Field(min_length=1)
    baseUrl: str
    credential: CredentialInjection
    tools: list[ToolDef]
    createdAt: str


# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------


class Tenant(BaseModel):
    id: str
    name: str = Field(min_length=1)
    createdAt: str


class User(BaseModel):
    id: str
    tenantId: str
    displayName: str = Field(min_length=1)
    email: str | None = None
    createdAt: str


class AgentIdentity(BaseModel):
    id: str
    tenantId: str
    name: str = Field(min_length=1)
    # Ed25519 public JWK; the agent proves possession of the private half.
    publicJwk: dict[str, Any]
    status: Literal["active", "disabled"]
    createdAt: str


class Operator(BaseModel):
    """A human operator of the control plane. Replaces the anonymous shared
    admin key: every control-plane mutation is attributed to an operator id in
    the audit chain. Only the SHA-256 of the operator key is stored."""

    id: str
    name: str = Field(min_length=1)
    role: Literal["owner", "approver", "auditor"]
    keyHash: str
    status: Literal["active", "disabled"]
    createdAt: str


# ---------------------------------------------------------------------------
# Authorization details (RFC 9396-flavored) and delegation grants
# ---------------------------------------------------------------------------


class AuthorizationDetail(BaseModel):
    type: Literal["toolgate:tool_call"] = "toolgate:tool_call"
    # Upstream name this detail applies to.
    upstream: str = Field(min_length=1)
    # Tool names, or ["*"] for all tools on the upstream.
    tools: list[str] = Field(min_length=1)


class Budget(BaseModel):
    maxUnits: int = Field(gt=0)
    spentUnits: int = Field(default=0, ge=0)


class DelegationGrant(BaseModel):
    """A delegation grant is the durable record of a human delegating bounded
    authority to an agent: which tools, how much budget, until when.
    Capability tokens are minted *from* grants and are always narrower or equal."""

    id: str
    tenantId: str
    userId: str
    agentId: str
    scopes: list[str]
    authorization: list[AuthorizationDetail] = Field(min_length=1)
    budget: Budget
    # Policy applied at the gate for calls under this grant.
    policyId: str
    expiresAt: str
    status: Literal["active", "revoked"]
    createdAt: str


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

ConstraintOp = Literal[
    "eq", "neq", "gt", "gte", "lt", "lte", "in", "contains", "startsWith", "matches"
]


class ArgConstraint(BaseModel):
    # Dot path into the tool call arguments, e.g. "to.email" or "amount".
    path: str = Field(min_length=1)
    op: ConstraintOp
    value: Any = None


class RuleMatch(BaseModel):
    # Glob over upstream name ("*" matches any run of characters). Absent = any.
    upstream: str | None = None
    # Glob over tool name. Absent = any.
    tool: str | None = None
    # All constraints must hold for the rule to match.
    where: list[ArgConstraint] | None = None


class RuleConstraints(BaseModel):
    # Calls costing more than this are denied even when the rule allows.
    maxCostUnits: int | None = Field(default=None, gt=0)


class RuleWhen(BaseModel):
    # Task-state predicate: the rule only matches when the current transaction
    # has (True) / has not (False) touched an untrusted-content tool. This is
    # the structural lethal-trifecta defense — e.g. "email is allowed, but not
    # in a task that has read untrusted content, unless a human approves".
    txnTouchedUntrusted: bool | None = None


class PolicyRule(BaseModel):
    id: str | None = None
    description: str | None = None
    effect: Literal["allow", "deny", "require_approval"]
    match: RuleMatch
    when: RuleWhen | None = None
    constraints: RuleConstraints | None = None


class Policy(BaseModel):
    id: str
    tenantId: str
    name: str = Field(min_length=1)
    # Rules are evaluated in order; first match wins. No match = deny.
    rules: list[PolicyRule]
    createdAt: str


# ---------------------------------------------------------------------------
# Approvals (async human-in-the-loop, CIBA-style)
# ---------------------------------------------------------------------------


class ApprovalRequest(BaseModel):
    id: str
    tenantId: str
    callId: str
    grantId: str
    agentId: str
    userId: str
    upstream: str
    tool: str
    args: dict[str, Any]
    # "executing" is a transient claim taken atomically before the upstream call
    # so two concurrent executes of one approval cannot both fire.
    status: Literal["pending", "approved", "denied", "expired", "executing", "executed"]
    requestedAt: str
    expiresAt: str
    decidedAt: str | None = None
    decidedBy: str | None = None
    executedAt: str | None = None


# ---------------------------------------------------------------------------
# Upstream OAuth brokering (#11): tenant provider apps + per-user connections
# ---------------------------------------------------------------------------


class ProviderApp(BaseModel):
    """A tenant-registered OAuth application at a third-party provider. The
    client secret is sealed in the vault; only its ref lives here."""

    id: str
    tenantId: str
    name: str = Field(min_length=1)
    clientId: str = Field(min_length=1)
    clientSecretRef: str
    authorizeUrl: str = Field(min_length=1)
    tokenUrl: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    createdAt: str


class Connection(BaseModel):
    """One user's authorized account at a provider. Token material lives only
    in the vault (refs here); revocation deletes the sealed tokens outright."""

    id: str
    tenantId: str
    userId: str
    providerAppId: str
    accessTokenRef: str
    refreshTokenRef: str | None = None
    # Access-token expiry (ISO); the broker refreshes transparently past it.
    expiresAt: str
    scopes: list[str] = Field(default_factory=list)
    status: Literal["active", "revoked"] = "active"
    createdAt: str
    updatedAt: str


# ---------------------------------------------------------------------------
# Approval notification channels (webhook, Slack, email magic links)
# ---------------------------------------------------------------------------


class WebhookChannelConfig(BaseModel):
    type: Literal["webhook"]
    url: str = Field(min_length=1)


class SlackChannelConfig(BaseModel):
    type: Literal["slack"]
    # Slack channel id the approval messages are posted to.
    channel: str = Field(min_length=1)
    # Sealed-secret refs: the bot token posts messages, the signing secret
    # verifies interactivity callbacks. Raw values never live in this object.
    botTokenRef: str
    signingSecretRef: str


class EmailRecipient(BaseModel):
    email: str = Field(min_length=3)
    # Decisions from this recipient's magic links are attributed to this operator.
    operatorId: str = Field(min_length=1)


class EmailChannelConfig(BaseModel):
    type: Literal["email"]
    smtpHost: str = Field(min_length=1)
    smtpPort: int = Field(default=587, gt=0)
    smtpUser: str | None = None
    smtpPasswordRef: str | None = None
    fromAddress: str = Field(min_length=3)
    useTls: bool = True
    recipients: list[EmailRecipient] = Field(min_length=1)


ChannelConfig = Annotated[
    WebhookChannelConfig | SlackChannelConfig | EmailChannelConfig,
    Field(discriminator="type"),
]


class NotificationChannel(BaseModel):
    id: str
    tenantId: str
    name: str = Field(min_length=1)
    config: ChannelConfig
    status: Literal["active", "disabled"] = "active"
    createdAt: str


class SlackBinding(BaseModel):
    """Maps a Slack user to an operator so Slack decisions carry real operator
    attribution. Unbound Slack users are refused."""

    tenantId: str
    slackUserId: str = Field(min_length=1)
    operatorId: str = Field(min_length=1)
    createdAt: str


class Delivery(BaseModel):
    """One notification attempt stream: channel x approval x event. Retried
    with backoff until delivered, failed, or attempts are exhausted."""

    id: str
    tenantId: str
    channelId: str
    channelType: Literal["webhook", "slack", "email"]
    approvalId: str
    event: Literal["parked", "decided", "expired"]
    status: Literal["pending", "delivered", "failed"]
    attempts: int = 0
    lastError: str | None = None
    nextAttemptAt: str
    createdAt: str
    updatedAt: str
    # Channel bookkeeping (e.g. Slack message ts for later chat.update).
    meta: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Capability token claims
# ---------------------------------------------------------------------------


class ActClaim(BaseModel):
    sub: str


class CnfClaim(BaseModel):
    # Confirmation claim (RFC 7800): JWK thumbprint of the agent key that must sign call proofs.
    jkt: str


class CapabilityClaims(BaseModel):
    """RFC 8693 delegation semantics: `sub` stays the human principal the work
    is for; `act.sub` is the agent actually acting. The agent never receives
    the user's credentials — only this narrow, short-lived, sender-bound token."""

    model_config = ConfigDict(extra="allow")

    iss: str
    sub: str
    aud: str
    exp: int
    iat: int
    jti: str
    tenant: str
    grant_id: str
    act: ActClaim
    scope: str
    authorization_details: list[AuthorizationDetail]
    cnf: CnfClaim
    # Per-task transaction id (Transaction Tokens alignment) — the audit join key.
    txn: str
    tg_ver: Literal[1]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

DecisionEffect = Literal["allow", "deny", "require_approval"]
DecisionSource = Literal[
    "token_bounds", "rule", "constraint", "budget", "approval", "default", "operator", "system"
]


class AuditDecision(BaseModel):
    effect: DecisionEffect
    source: DecisionSource
    ruleId: str | None = None
    reason: str


class AuditResult(BaseModel):
    status: Literal["executed", "denied", "pending_approval", "error"]
    httpStatus: int | None = None
    latencyMs: float | None = None
    costUnits: int | None = None


class AuditActor(BaseModel):
    agentId: str
    userId: str
    grantId: str
    tokenJti: str


class AuditAction(BaseModel):
    callId: str
    upstream: str
    tool: str
    # SHA-256 of canonical args — proves what was requested without storing payloads.
    argsHash: str


class AuditRecordInput(BaseModel):
    id: str
    tenantId: str
    ts: str
    actor: AuditActor
    action: AuditAction
    decision: AuditDecision
    result: AuditResult
    # Structured extras (e.g. key-rotation handoffs carry {"newKid": ...}).
    # Optional and dropped when absent, so legacy record hashes are unchanged.
    meta: dict[str, Any] | None = None


class AuditRecord(AuditRecordInput):
    seq: int = Field(gt=0)
    prevHash: str
    hash: str
    sig: str
    # kid of the gate key that signed this record; absent on legacy records
    # (verified against the root key). A new kid is only trusted after a
    # handoff record signed by a previously-trusted kid names it in meta.newKid.
    sigKid: str | None = None


class Checkpoint(BaseModel):
    """A signed Merkle commitment over the first `seq` audit records. Anchoring
    checkpoints externally makes history rewriting detectable even if the gate
    signing key is later compromised."""

    seq: int = Field(gt=0)
    root: str
    ts: str
    sigKid: str | None = None
    sig: str
    # Transparency-log evidence ({logId, logIndex, uuid, rootHash, treeSize,
    # hashes, signedRoot}), attached AFTER signing — additive and excluded from
    # the signed body, so legacy checkpoint signatures stay valid.
    anchor: dict[str, Any] | None = None
