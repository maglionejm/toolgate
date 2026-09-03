import time
from dataclasses import dataclass
from typing import Any

import httpx

from toolgate.core import sign_client_assertion, sign_pop_proof


class ToolgateCallError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        http_status: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details


@dataclass(frozen=True)
class TokenGrant:
    access_token: str
    expires_at: float
    txn: str


@dataclass(frozen=True)
class CallResult:
    status: str  # "executed"
    call_id: str
    result: Any


@dataclass(frozen=True)
class PendingApproval:
    status: str  # "pending_approval"
    approval_id: str
    expires_at: str
    reason: str


class ToolgateClient:
    """Agent-side client. Holds no upstream credentials — only the agent
    keypair. Handles token exchange (with refresh margin), PoP proof signing
    per call, and the approval wait flow."""

    def __init__(
        self,
        *,
        base_url: str,
        agent_id: str,
        agent_private_jwk: dict[str, Any],
        grant_id: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._agent_id = agent_id
        self._agent_private_jwk = agent_private_jwk
        self._grant_id = grant_id
        self._http = http_client or httpx.Client(timeout=30.0)
        self._token: TokenGrant | None = None

    def token(self) -> TokenGrant:
        """Exchange the client assertion for a capability token (cached until near expiry)."""
        if self._token and self._token.expires_at - time.time() > 10:
            return self._token

        token_url = f"{self._base_url}/v1/token"
        assertion = sign_client_assertion(
            self._agent_private_jwk, agent_id=self._agent_id, token_url=token_url
        )
        res = self._http.post(
            token_url,
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": self._grant_id,
            },
        )
        body = _json_body(res)
        if res.status_code != 200 or "access_token" not in body:
            raise _error_from(res.status_code, body)
        self._token = TokenGrant(
            access_token=body["access_token"],
            expires_at=time.time() + body.get("expires_in", 60),
            txn=body.get("txn", ""),
        )
        return self._token

    def call(
        self, upstream: str, tool: str, args: dict[str, Any] | None = None
    ) -> CallResult | PendingApproval:
        """Call a tool through the gate. Returns the executed result or a
        pending approval handle; raises ToolgateCallError on denial/budget/
        revocation."""
        res = self._signed_post(f"/v1/gate/call/{upstream}", {"tool": tool, "args": args or {}})
        body = _json_body(res)

        if res.status_code == 202:
            return PendingApproval(
                status="pending_approval",
                approval_id=body["approval_id"],
                expires_at=body["expires_at"],
                reason=body.get("reason", "approval required"),
            )
        if res.status_code >= 400:
            raise _error_from(res.status_code, body)
        return CallResult(status="executed", call_id=body["call_id"], result=body["result"])

    def wait_for_approval(
        self, approval_id: str, *, poll_seconds: float = 1.5, timeout_seconds: float = 120
    ) -> CallResult:
        """Poll an approval until it is decided, then execute it."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            status = self.approval_status(approval_id)
            if status == "approved":
                return self.execute_approval(approval_id)
            if status in ("denied", "expired"):
                raise ToolgateCallError("TG_APPROVAL_DENIED", f"approval {status}", 403)
            if status == "executed":
                raise ToolgateCallError("TG_APPROVAL_DENIED", "approval already executed", 403)
            time.sleep(poll_seconds)
        raise ToolgateCallError("TG_APPROVAL_PENDING", "timed out waiting for approval", 202)

    def approval_status(self, approval_id: str) -> str:
        grant = self.token()
        # The gate now requires a PoP proof on this GET (sender-binding), not just
        # the bearer token — sign one exactly as the POST paths do.
        htu = f"{self._base_url}/v1/gate/approvals/{approval_id}"
        proof = sign_pop_proof(
            self._agent_private_jwk,
            htm="GET",
            htu=htu,
            access_token=grant.access_token,
        )
        res = self._http.get(
            htu,
            headers={
                "authorization": f"Bearer {grant.access_token}",
                "x-toolgate-proof": proof,
            },
        )
        body = _json_body(res)
        if res.status_code >= 400:
            raise _error_from(res.status_code, body)
        return body["status"]

    def execute_approval(self, approval_id: str) -> CallResult:
        res = self._signed_post(f"/v1/gate/approvals/{approval_id}/execute", None)
        body = _json_body(res)
        if res.status_code >= 400:
            raise _error_from(res.status_code, body)
        return CallResult(status="executed", call_id=body["call_id"], result=body["result"])

    def _signed_post(self, path: str, body: dict[str, Any] | None) -> httpx.Response:
        grant = self.token()
        proof = sign_pop_proof(
            self._agent_private_jwk,
            htm="POST",
            htu=f"{self._base_url}{path}",
            access_token=grant.access_token,
        )
        headers = {"authorization": f"Bearer {grant.access_token}", "x-toolgate-proof": proof}
        if body is not None:
            return self._http.post(f"{self._base_url}{path}", headers=headers, json=body)
        return self._http.post(f"{self._base_url}{path}", headers=headers)


def _error_from(http_status: int, body: dict[str, Any]) -> ToolgateCallError:
    err = body.get("error", {}) if isinstance(body, dict) else {}
    return ToolgateCallError(
        err.get("code", "TG_INTERNAL"),
        err.get("message", f"gate returned {http_status}"),
        http_status,
        err.get("details"),
    )


def _json_body(res: httpx.Response) -> Any:
    """Parse a JSON response body, surfacing a non-JSON body as the SDK's typed
    error (carrying the HTTP status) rather than a raw ``json.JSONDecodeError``."""
    try:
        return res.json()
    except ValueError as err:
        raise ToolgateCallError(
            "TG_INTERNAL",
            f"non-JSON response from gate (HTTP {res.status_code})",
            res.status_code,
        ) from err
