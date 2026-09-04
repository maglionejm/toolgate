from typing import Any


class ErrorCodes:
    TOKEN_INVALID = "TG_TOKEN_INVALID"
    TOKEN_EXPIRED = "TG_TOKEN_EXPIRED"
    PROOF_INVALID = "TG_PROOF_INVALID"
    DENIED = "TG_DENIED"
    APPROVAL_REQUIRED = "TG_APPROVAL_REQUIRED"
    APPROVAL_DENIED = "TG_APPROVAL_DENIED"
    APPROVAL_PENDING = "TG_APPROVAL_PENDING"
    BUDGET_EXCEEDED = "TG_BUDGET_EXCEEDED"
    RATE_LIMITED = "TG_RATE_LIMITED"
    REVOKED = "TG_REVOKED"
    NOT_FOUND = "TG_NOT_FOUND"
    VALIDATION = "TG_VALIDATION"
    UPSTREAM_ERROR = "TG_UPSTREAM_ERROR"
    INTERNAL = "TG_INTERNAL"
    # OAuth brokering (#11): the grant's user has no active connection for the
    # upstream's provider / the broker could not obtain a live token.
    CONNECTION_REQUIRED = "TG_CONNECTION_REQUIRED"
    CONNECTION_FAILED = "TG_CONNECTION_FAILED"


_HTTP_STATUS: dict[str, int] = {
    ErrorCodes.TOKEN_INVALID: 401,
    ErrorCodes.TOKEN_EXPIRED: 401,
    ErrorCodes.PROOF_INVALID: 401,
    ErrorCodes.DENIED: 403,
    ErrorCodes.APPROVAL_REQUIRED: 202,
    ErrorCodes.APPROVAL_DENIED: 403,
    ErrorCodes.APPROVAL_PENDING: 202,
    ErrorCodes.BUDGET_EXCEEDED: 403,
    ErrorCodes.RATE_LIMITED: 429,
    ErrorCodes.REVOKED: 403,
    ErrorCodes.NOT_FOUND: 404,
    ErrorCodes.VALIDATION: 400,
    ErrorCodes.UPSTREAM_ERROR: 502,
    ErrorCodes.INTERNAL: 500,
    ErrorCodes.CONNECTION_REQUIRED: 403,
    ErrorCodes.CONNECTION_FAILED: 502,
}


class ToolgateError(Exception):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = _HTTP_STATUS.get(code, 500)
        self.details = details

    def to_json(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return {"error": error}
