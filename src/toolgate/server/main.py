import os

import uvicorn

from .app import create_app
from .context import create_app_context


def main() -> None:
    port = int(os.environ.get("PORT", "8484"))
    ctx = create_app_context(
        public_url=os.environ.get("TOOLGATE_PUBLIC_URL", f"http://localhost:{port}")
    )
    print(f"[toolgate] control plane + gate listening on :{port}")
    print(f"[toolgate] issuer: {ctx.config.issuer}")
    print(f"[toolgate] admin key: {ctx.config.admin_key}")
    uvicorn.run(create_app(ctx), host="0.0.0.0", port=port, log_level="warning")


if __name__ == "__main__":
    main()
