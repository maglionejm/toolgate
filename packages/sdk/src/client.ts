import {
  signClientAssertion,
  signPopProof,
  type JWK,
  type ToolgateErrorCode,
} from "@toolgate/core";

export interface ToolgateClientOptions {
  /** Toolgate base URL, e.g. https://gate.example.com */
  baseUrl: string;
  agentId: string;
  /** The agent's Ed25519 private JWK. The only secret an agent ever holds. */
  agentPrivateJwk: JWK;
  grantId: string;
  fetchImpl?: typeof fetch;
}

export interface TokenGrant {
  accessToken: string;
  expiresAt: number;
  txn: string;
}

export interface CallResult {
  status: "executed";
  callId: string;
  result: unknown;
}

export interface PendingApproval {
  status: "pending_approval";
  approvalId: string;
  expiresAt: string;
  reason: string;
}

export class ToolgateCallError extends Error {
  readonly code: ToolgateErrorCode;
  readonly httpStatus: number;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: ToolgateErrorCode, message: string, httpStatus: number, details?: Record<string, unknown>) {
    super(message);
    this.name = "ToolgateCallError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.details = details;
  }
}

/**
 * Agent-side client. Holds no upstream credentials — only the agent keypair.
 * Handles token exchange (with refresh margin), PoP proof signing per call,
 * and the approval wait flow.
 */
export class ToolgateClient {
  readonly #o: Required<Omit<ToolgateClientOptions, "fetchImpl">>;
  readonly #fetch: typeof fetch;
  #token: TokenGrant | null = null;

  constructor(options: ToolgateClientOptions) {
    this.#o = {
      baseUrl: options.baseUrl.replace(/\/$/, ""),
      agentId: options.agentId,
      agentPrivateJwk: options.agentPrivateJwk,
      grantId: options.grantId,
    };
    this.#fetch = options.fetchImpl ?? fetch;
  }

  /** Exchange the client assertion for a capability token (cached until near expiry). */
  async token(): Promise<TokenGrant> {
    if (this.#token && this.#token.expiresAt - Date.now() > 10_000) return this.#token;

    const tokenUrl = `${this.#o.baseUrl}/v1/token`;
    const assertion = await signClientAssertion(this.#o.agentPrivateJwk, {
      agentId: this.#o.agentId,
      tokenUrl,
    });
    const res = await this.#fetch(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_assertion: assertion,
        grant_id: this.#o.grantId,
      }),
    });
    const json = (await res.json()) as {
      access_token?: string;
      expires_in?: number;
      txn?: string;
      error?: { code: ToolgateErrorCode; message: string; details?: Record<string, unknown> };
    };
    if (!res.ok || !json.access_token) {
      const err = json.error ?? { code: "TG_TOKEN_INVALID" as const, message: "token exchange failed" };
      throw new ToolgateCallError(err.code, err.message, res.status, err.details);
    }
    this.#token = {
      accessToken: json.access_token,
      expiresAt: Date.now() + (json.expires_in ?? 60) * 1000,
      txn: json.txn ?? "",
    };
    return this.#token;
  }

  /**
   * Call a tool through the gate. Returns the executed result or a pending
   * approval handle; throws ToolgateCallError on denial/budget/revocation.
   */
  async call(
    upstream: string,
    tool: string,
    args: Record<string, unknown> = {},
  ): Promise<CallResult | PendingApproval> {
    const path = `/v1/gate/call/${upstream}`;
    const res = await this.#signedPost(path, { tool, args });
    const json = (await res.json()) as Record<string, unknown>;

    if (res.status === 202) {
      return {
        status: "pending_approval",
        approvalId: json.approval_id as string,
        expiresAt: json.expires_at as string,
        reason: (json.reason as string) ?? "approval required",
      };
    }
    if (!res.ok) throw errorFrom(res.status, json);
    return {
      status: "executed",
      callId: json.call_id as string,
      result: json.result,
    };
  }

  /** Poll an approval until it is decided, then execute it. */
  async waitForApproval(
    approvalId: string,
    options: { pollMs?: number; timeoutMs?: number } = {},
  ): Promise<CallResult> {
    const pollMs = options.pollMs ?? 1500;
    const deadline = Date.now() + (options.timeoutMs ?? 120_000);

    while (Date.now() < deadline) {
      const status = await this.approvalStatus(approvalId);
      if (status === "approved") return this.executeApproval(approvalId);
      if (status === "denied" || status === "expired") {
        throw new ToolgateCallError("TG_APPROVAL_DENIED", `approval ${status}`, 403);
      }
      if (status === "executed") {
        throw new ToolgateCallError("TG_APPROVAL_DENIED", "approval already executed", 403);
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new ToolgateCallError("TG_APPROVAL_PENDING", "timed out waiting for approval", 202);
  }

  async approvalStatus(approvalId: string): Promise<string> {
    const { accessToken } = await this.token();
    const res = await this.#fetch(`${this.#o.baseUrl}/v1/gate/approvals/${approvalId}`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const json = (await res.json()) as Record<string, unknown>;
    if (!res.ok) throw errorFrom(res.status, json);
    return json.status as string;
  }

  async executeApproval(approvalId: string): Promise<CallResult> {
    const path = `/v1/gate/approvals/${approvalId}/execute`;
    const res = await this.#signedPost(path);
    const json = (await res.json()) as Record<string, unknown>;
    if (!res.ok) throw errorFrom(res.status, json);
    return { status: "executed", callId: json.call_id as string, result: json.result };
  }

  async #signedPost(path: string, body?: unknown): Promise<Response> {
    const { accessToken } = await this.token();
    const proof = await signPopProof(this.#o.agentPrivateJwk, {
      htm: "POST",
      htu: `${this.#o.baseUrl}${path}`,
      accessToken,
    });
    return this.#fetch(`${this.#o.baseUrl}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "x-toolgate-proof": proof,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  }
}

function errorFrom(httpStatus: number, json: Record<string, unknown>): ToolgateCallError {
  const err = (json.error ?? {}) as {
    code?: ToolgateErrorCode;
    message?: string;
    details?: Record<string, unknown>;
  };
  return new ToolgateCallError(
    err.code ?? "TG_INTERNAL",
    err.message ?? `gate returned ${httpStatus}`,
    httpStatus,
    err.details,
  );
}
