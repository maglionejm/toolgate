"""OpenAI tools-format adapter. Dependency-free: emits plain dicts in the
`tools=[...]` schema every OpenAI-compatible API accepts, plus a dispatcher
that routes tool calls through the gate."""

from collections.abc import Callable
from typing import Any

from toolgate.sdk import PendingApproval, ToolgateClient

TOOL_SEPARATOR = "__"


def openai_tools(
    client: ToolgateClient,
) -> tuple[list[dict[str, Any]], Callable[[str, dict[str, Any]], dict[str, Any]]]:
    """Returns (tools, dispatch).

    `tools` plugs into an OpenAI-compatible chat/agents call; `dispatch(name,
    arguments)` executes the model's tool call through the gate and returns a
    JSON-safe dict — including a structured `pending_approval` outcome so the
    agent loop can surface human-in-the-loop states instead of failing."""
    tools = [
        {
            "type": "function",
            "function": {
                "name": f"{t['upstream']}{TOOL_SEPARATOR}{t['name']}",
                "description": t["description"]
                or f"{t['name']} on {t['upstream']} (cost {t['costUnits']})",
                "parameters": t["argsSchema"],
            },
        }
        for t in client.list_tools()
    ]

    def dispatch(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        upstream, _, tool = name.partition(TOOL_SEPARATOR)
        if not tool:
            return {"error": f"tool name must be upstream{TOOL_SEPARATOR}tool, got {name!r}"}
        outcome = client.call(upstream, tool, arguments)
        if isinstance(outcome, PendingApproval):
            return {
                "status": "pending_approval",
                "approval_id": outcome.approval_id,
                "reason": outcome.reason,
            }
        return {"status": "executed", "result": outcome.result}

    return tools, dispatch
