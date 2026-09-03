from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from toolgate.core import ToolgateError

from .context import AppContext
from .control import control_router, token_router
from .gate import gate_router


def create_app(ctx: AppContext) -> FastAPI:
    app = FastAPI(title="toolgate", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, object]:
        return {"ok": True, "issuer": ctx.config.issuer, "control_kid": ctx.control_keys.kid}

    app.include_router(control_router(ctx))
    app.include_router(token_router(ctx))
    app.include_router(gate_router(ctx))

    @app.exception_handler(ToolgateError)
    async def toolgate_error_handler(_request: Request, err: ToolgateError) -> JSONResponse:
        # 202-class codes are flow states, not failures; they are returned
        # inline by handlers — reaching here means a real rejection.
        status = 409 if err.http_status == 202 else err.http_status
        return JSONResponse(status_code=status, content=err.to_json())

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
