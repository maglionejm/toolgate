import hashlib
import os
import sys

import uvicorn

from .app import create_app
from .context import create_app_context


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _admin_key_fingerprint(admin_key: str) -> str:
    # Never log the admin credential itself: a stdout line ends up in journald /
    # Docker / Cloud Logging forever. A short digest lets an operator confirm
    # *which* key is loaded without exposing it.
    return hashlib.sha256(admin_key.encode()).hexdigest()[:12]


def main() -> None:
    port = int(os.environ.get("PORT", "8484"))
    # Loopback by default; opt in to a routable interface explicitly. Binding
    # 0.0.0.0 with no TLS exposes the control plane (admin key, tokens, proofs)
    # in cleartext to the whole network.
    host = os.environ.get("TOOLGATE_HOST", "127.0.0.1")
    # Fail closed in production: without TOOLGATE_DEV a missing master/admin key
    # aborts the boot instead of silently self-provisioning a fallback.
    dev_mode = _truthy(os.environ.get("TOOLGATE_DEV"))
    try:
        ctx = create_app_context(
            public_url=os.environ.get("TOOLGATE_PUBLIC_URL", f"http://localhost:{port}"),
            dev_mode=dev_mode,
        )
    except RuntimeError as err:
        print(f"[toolgate] refusing to start: {err}", file=sys.stderr)
        raise SystemExit(1) from err

    print(f"[toolgate] control plane + gate listening on {host}:{port}")
    print(f"[toolgate] issuer: {ctx.config.issuer}")
    print(f"[toolgate] admin key fingerprint: {_admin_key_fingerprint(ctx.config.admin_key)}")
    if host == "0.0.0.0":  # noqa: S104 - explicit operator opt-in, warned below
        print(
            "[toolgate] WARNING: bound to 0.0.0.0 — ensure TLS termination is in front "
            "of this process; the control plane must not be reachable in cleartext.",
            file=sys.stderr,
        )
    uvicorn.run(create_app(ctx), host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
