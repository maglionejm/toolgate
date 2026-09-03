from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from toolgate.core import ErrorCodes, ToolgateError

from .context import AppContext
from .control import control_router, token_router
from .gate import gate_router

# Reject oversized request bodies before they are buffered/parsed. Tool-call
# args are small; a multi-megabyte body is either abuse or a mistake, and it
# feeds the canonical-hash and approval-storage paths.
MAX_BODY_BYTES = 1_000_000

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    # Capability tokens and gate responses must never be cached by an
    # intermediary — a classic bearer-token leak channel.
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def create_app(ctx: AppContext) -> FastAPI:
    # openapi_url=None: the schema described the full control plane and was served
    # unauthenticated even with the docs UIs disabled.
    app = FastAPI(title="toolgate", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def guard_and_harden(request: Request, call_next):  # type: ignore[no-untyped-def]
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": ErrorCodes.VALIDATION,
                                "message": f"request body exceeds {MAX_BODY_BYTES} bytes",
                            }
                        },
                    )
            except ValueError:
                pass
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, object]:
        return {"ok": True, "issuer": ctx.config.issuer, "control_kid": ctx.control_keys.kid}

    @app.get("/v1/keys")
    async def public_keys() -> dict[str, object]:
        """Public verification material: lets anyone verify capability tokens
        and independently verify exported audit chains offline."""
        return {
            "issuer": ctx.config.issuer,
            "gate_audience": ctx.config.gate_audience,
            "proof_versions": [2],
            # Newest keys (compat with pre-rotation clients)...
            "control": ctx.control_keys.public_jwk,
            "gate": ctx.gate_keys.public_jwk,
            # ...and the full rotation keysets for kid-aware verifiers.
            "control_jwks": {"keys": [k.public_jwk for k in ctx.control_keyset]},
            "gate_jwks": {"keys": [k.public_jwk for k in ctx.gate_keyset]},
        }

    app.include_router(control_router(ctx))
    app.include_router(token_router(ctx))
    app.include_router(gate_router(ctx))

    @app.exception_handler(ToolgateError)
    async def toolgate_error_handler(_request: Request, err: ToolgateError) -> JSONResponse:
        # 202-class codes are flow states, not failures; they are returned
        # inline by handlers — reaching here means a real rejection.
        status = 409 if err.http_status == 202 else err.http_status
        return JSONResponse(status_code=status, content=err.to_json())

    @app.exception_handler(RecursionError)
    async def recursion_error_handler(_request: Request, _err: RecursionError) -> JSONResponse:
        # A deeply nested args payload overflows the canonical-JSON hasher. Turn
        # it into a clean 400 rather than an uncaught 500 on a valid-bearer path.
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": ErrorCodes.VALIDATION,
                    "message": "request payload is too deeply nested",
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, err: RequestValidationError
    ) -> JSONResponse:
        issues = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in err.errors()]
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "TG_VALIDATION",
                    "message": "invalid request body",
                    "details": {"issues": issues},
                }
            },
        )

    return app
