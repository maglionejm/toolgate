"""MCP surface: exposes each capability token's reachable tools as a Model
Context Protocol server (Streamable HTTP, JSON-RPC 2.0).

Authentication is the bearer capability token only. MCP clients cannot produce
Toolgate PoP proofs, so this surface deliberately trades sender-binding for
ecosystem compatibility — mitigated by short jittered TTLs, audience binding,
and the unchanged policy/budget/audit pipeline underneath. Deployments that
refuse that trade set `mcp_enabled = False`. (ADR 0009.)
"""

import json
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from toolgate import __version__
from toolgate.core import ToolgateError

from .context import AppContext
from .gate import _authenticate_token_only, reachable_tools, run_gate_call

MCP_PROTOCOL_VERSION = "2025-06-18"

# JSON-RPC error codes: -32009 approval pending (retryable by design),
# -32010 gate rejection (carries the Toolgate error envelope in data).
APPROVAL_PENDING_CODE = -32009
GATE_ERROR_CODE = -32010


def _rpc_error(req_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _rpc_result(req_id: Any, result: dict[str, Any]) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def mcp_router(ctx: AppContext) -> APIRouter:
    router = APIRouter()

    @router.post("/v1/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        if not ctx.config.mcp_enabled:
            return JSONResponse(status_code=404, content={"error": {"code": "TG_NOT_FOUND"}})

        authed = await _authenticate_token_only(ctx, request)
        try:
            message = json.loads(await request.body())
        except ValueError:
            return JSONResponse(
                status_code=400, content=_rpc_error(None, -32700, "parse error")
            )
        if isinstance(message, list):
            return JSONResponse(
                status_code=400,
                content=_rpc_error(None, -32600, "batch requests are not supported"),
            )

        method = message.get("method")
        req_id = message.get("id")
        params = message.get("params") or {}

        # Notifications get an empty 202 per Streamable HTTP.
        if req_id is None:
            return Response(status_code=202)

        if method == "initialize":
            return JSONResponse(
                _rpc_result(
                    req_id,
                    {
                        "protocolVersion": params.get("protocolVersion", MCP_PROTOCOL_VERSION),
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "toolgate", "version": __version__},
                    },
                )
            )

        if method == "ping":
            return JSONResponse(_rpc_result(req_id, {}))

        if method == "tools/list":
            tools = [
                {
                    "name": f"{t['upstream']}__{t['name']}",
                    "description": t["description"]
                    or f"{t['name']} on {t['upstream']} (cost {t['costUnits']})",
                    "inputSchema": t["argsSchema"],
                }
                for t in reachable_tools(ctx, authed.claims)
            ]
            return JSONResponse(_rpc_result(req_id, {"tools": tools}))

        if method == "tools/call":
            name = params.get("name", "")
            upstream, _, tool = name.partition("__")
            if not tool:
                return JSONResponse(
                    _rpc_error(req_id, -32602, f"tool name must be upstream__tool, got {name!r}")
                )
            arguments = params.get("arguments") or {}
            try:
                outcome = await run_gate_call(
                    ctx, authed.claims, authed.grant, upstream, tool, arguments
                )
            except ToolgateError as err:
                return JSONResponse(
                    _rpc_error(
                        req_id,
                        GATE_ERROR_CODE,
                        err.message,
                        {"code": err.code, **(err.details or {})},
                    )
                )
            if outcome.status == "pending_approval":
                return JSONResponse(
                    _rpc_error(
                        req_id,
                        APPROVAL_PENDING_CODE,
                        "call parked for human approval",
                        {
                            "approval_id": outcome.approval_id,
                            "expires_at": outcome.expires_at,
                            "reason": outcome.reason,
                        },
                    )
                )
            return JSONResponse(
                _rpc_result(
                    req_id,
                    {
                        "content": [{"type": "text", "text": json.dumps(outcome.result)}],
                        "isError": False,
                    },
                )
            )

        return JSONResponse(_rpc_error(req_id, -32601, f"method not found: {method}"))

    return router
