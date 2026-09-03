from typing import Any

import httpx
import typer
from rich.console import Console

from .config import Profile

err_console = Console(stderr=True)


class AdminClient:
    """Thin, honest wrapper over the control-plane API. Any non-2xx response is
    rendered as the server's error envelope and exits non-zero."""

    def __init__(self, profile: Profile) -> None:
        self.url = profile.url
        self._http = httpx.Client(
            base_url=profile.url,
            headers={"x-toolgate-admin-key": profile.admin_key},
            timeout=15.0,
        )

    def get(self, path: str, **params: Any) -> Any:
        return self._handle(
            self._http.get(path, params={k: v for k, v in params.items() if v is not None})
        )

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._handle(self._http.post(path, json=body or {}))

    def public(self, path: str) -> Any:
        # Unauthenticated endpoints (/healthz, /v1/keys).
        return self._handle(httpx.get(f"{self.url}{path}", timeout=15.0))

    def _handle(self, res: httpx.Response) -> Any:
        try:
            body = res.json()
        except ValueError:
            body = {"error": {"code": "TG_INTERNAL", "message": res.text[:200]}}
        if res.status_code >= 400:
            err = body.get("error", {})
            err_console.print(
                f"[bold red]{err.get('code', res.status_code)}[/] {err.get('message', '')}"
            )
            if err.get("details"):
                err_console.print(f"[dim]{err['details']}[/]")
            raise typer.Exit(1)
        return body
