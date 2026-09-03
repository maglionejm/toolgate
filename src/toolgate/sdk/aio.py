"""Async agent-side client — same contract as the sync ToolgateClient, built
for async-native agent frameworks (LangGraph, OpenAI Agents, MCP hosts)."""

import asyncio
import json
import time
from typing import Any

import httpx

from toolgate.core import sign_client_assertion, sign_pop_proof

from .client import CallResult, PendingApproval, TokenGrant, ToolgateCallError, _error_from


class AsyncToolgateClient:
    def __init__(
        self,
        *,
        base_url: str,
        agent_id: str,
        agent_private_jwk: dict[str, Any],
        grant_id: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._agent_id = agent_id
        self._agent_private_jwk = agent_private_jwk
        self._grant_id = grant_id
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._token: TokenGrant | None = None

    async def token(self) -> TokenGrant:
        if self._token and self._token.expires_at - time.time() > 10:
            return self._token
        token_url = f"{self._base_url}/v1/token"
        assertion = sign_client_assertion(
            self._agent_private_jwk, agent_id=self._agent_id, token_url=token_url
        )
        res = await self._http.post(
            token_url,
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": self._grant_id,
            },
        )
        body = res.json()
        if res.status_code != 200 or "access_token" not in body:
            raise _error_from(res.status_code, body)
        self._token = TokenGrant(
            access_token=body["access_token"],
            expires_at=time.time() + body.get("expires_in", 60),
            txn=body.get("txn", ""),
        )
        return self._token

    async def call(
        self, upstream: str, tool: str, args: dict[str, Any] | None = None
    ) -> CallResult | PendingApproval:
        res = await self._signed_post(
            f"/v1/gate/call/{upstream}", {"tool": tool, "args": args or {}}
        )
        body = res.json()
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

    async def list_tools(self) -> list[dict[str, Any]]:
        """The tools this grant's tokens can actually reach — the discovery
        surface used by the framework adapters."""
        grant = await self.token()
        res = await self._http.get(
            f"{self._base_url}/v1/gate/tools",
            headers={"authorization": f"Bearer {grant.access_token}"},
        )
        body = res.json()
        if res.status_code >= 400:
            raise _error_from(res.status_code, body)
        return body

    async def wait_for_approval(
        self, approval_id: str, *, poll_seconds: float = 1.5, timeout_seconds: float = 120
    ) -> CallResult:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            status = await self.approval_status(approval_id)
            if status == "approved":
                return await self.execute_approval(approval_id)
            if status in ("denied", "expired"):
                raise ToolgateCallError("TG_APPROVAL_DENIED", f"approval {status}", 403)
            if status == "executed":
                raise ToolgateCallError("TG_APPROVAL_DENIED", "approval already executed", 403)
            await asyncio.sleep(poll_seconds)
        raise ToolgateCallError("TG_APPROVAL_PENDING", "timed out waiting for approval", 202)

    async def approval_status(self, approval_id: str) -> str:
        res = await self._signed_get(f"/v1/gate/approvals/{approval_id}")
        body = res.json()
        if res.status_code >= 400:
            raise _error_from(res.status_code, body)
        return body["status"]

    async def execute_approval(self, approval_id: str) -> CallResult:
        res = await self._signed_post(f"/v1/gate/approvals/{approval_id}/execute", None)
        body = res.json()
        if res.status_code >= 400:
            raise _error_from(res.status_code, body)
        return CallResult(status="executed", call_id=body["call_id"], result=body["result"])

    async def _signed_post(self, path: str, body: dict[str, Any] | None) -> httpx.Response:
        grant = await self.token()
        body_bytes = json.dumps(body).encode() if body is not None else None
        proof = sign_pop_proof(
            self._agent_private_jwk,
            htm="POST",
            htu=f"{self._base_url}{path}",
            access_token=grant.access_token,
            body=body_bytes,
        )
        headers = {"authorization": f"Bearer {grant.access_token}", "x-toolgate-proof": proof}
        if body_bytes is not None:
            headers["content-type"] = "application/json"
            return await self._http.post(
                f"{self._base_url}{path}", headers=headers, content=body_bytes
            )
        return await self._http.post(f"{self._base_url}{path}", headers=headers)

    async def _signed_get(self, path: str) -> httpx.Response:
        grant = await self.token()
        proof = sign_pop_proof(
            self._agent_private_jwk,
            htm="GET",
            htu=f"{self._base_url}{path}",
            access_token=grant.access_token,
        )
        return await self._http.get(
            f"{self._base_url}{path}",
            headers={"authorization": f"Bearer {grant.access_token}", "x-toolgate-proof": proof},
        )
