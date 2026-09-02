export const ErrorCodes = {
  TOKEN_INVALID: "TG_TOKEN_INVALID",
  TOKEN_EXPIRED: "TG_TOKEN_EXPIRED",
  PROOF_INVALID: "TG_PROOF_INVALID",
  DENIED: "TG_DENIED",
  APPROVAL_REQUIRED: "TG_APPROVAL_REQUIRED",
  APPROVAL_DENIED: "TG_APPROVAL_DENIED",
  APPROVAL_PENDING: "TG_APPROVAL_PENDING",
  BUDGET_EXCEEDED: "TG_BUDGET_EXCEEDED",
  RATE_LIMITED: "TG_RATE_LIMITED",
  REVOKED: "TG_REVOKED",
  NOT_FOUND: "TG_NOT_FOUND",
  VALIDATION: "TG_VALIDATION",
  UPSTREAM_ERROR: "TG_UPSTREAM_ERROR",
  INTERNAL: "TG_INTERNAL",
} as const;

export type ToolgateErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

const HTTP_STATUS: Record<ToolgateErrorCode, number> = {
  TG_TOKEN_INVALID: 401,
  TG_TOKEN_EXPIRED: 401,
  TG_PROOF_INVALID: 401,
  TG_DENIED: 403,
  TG_APPROVAL_REQUIRED: 202,
  TG_APPROVAL_DENIED: 403,
  TG_APPROVAL_PENDING: 202,
  TG_BUDGET_EXCEEDED: 403,
  TG_RATE_LIMITED: 429,
  TG_REVOKED: 403,
  TG_NOT_FOUND: 404,
  TG_VALIDATION: 400,
  TG_UPSTREAM_ERROR: 502,
  TG_INTERNAL: 500,
};

export class ToolgateError extends Error {
  readonly code: ToolgateErrorCode;
  readonly httpStatus: number;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: ToolgateErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ToolgateError";
    this.code = code;
    this.httpStatus = HTTP_STATUS[code];
    this.details = details;
  }

  toJSON(): { error: { code: ToolgateErrorCode; message: string; details?: Record<string, unknown> } } {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }
}
