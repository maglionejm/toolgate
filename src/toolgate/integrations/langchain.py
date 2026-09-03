"""LangChain adapter (optional dependency: langchain-core)."""

from typing import Any

from toolgate.sdk import PendingApproval, ToolgateClient


def langchain_tools(client: ToolgateClient) -> list[Any]:
    """Reachable tools as LangChain StructuredTools. Parked approvals are
    returned as structured content so LangGraph interrupts can surface them."""
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as err:  # pragma: no cover - exercised only without extra
        raise ImportError(
            "langchain-core is required for langchain_tools(): "
            "pip install 'toolgate-io[langchain]'"
        ) from err

    def make_tool(meta: dict[str, Any]) -> Any:
        upstream, tool = meta["upstream"], meta["name"]

        def run(**kwargs: Any) -> dict[str, Any]:
            outcome = client.call(upstream, tool, kwargs)
            if isinstance(outcome, PendingApproval):
                return {
                    "status": "pending_approval",
                    "approval_id": outcome.approval_id,
                    "reason": outcome.reason,
                }
            return {"status": "executed", "result": outcome.result}

        return StructuredTool.from_function(
            func=run,
            name=f"{upstream}__{tool}",
            description=meta["description"] or f"{tool} on {upstream}",
        )

    return [make_tool(meta) for meta in client.list_tools()]
