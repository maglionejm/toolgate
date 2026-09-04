"""OAuth broker (#11): per-user third-party connections.

Toolgate is the OAuth client toward real SaaS providers. Users authorize once
through an authorization-code + PKCE flow; the broker custodies the sealed
refresh token and injects live access tokens into gated calls at execution —
the agent never sees a token, exactly like static secrets.
"""

import asyncio
import base64
import hashlib
import secrets
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx

from toolgate.core import Connection, ErrorCodes, ProviderApp, ToolgateError, new_id

from .store import Store
from .vault import Vault

STATE_TTL_SECONDS = 600
# Refresh ahead of expiry so an injected token never dies mid-flight upstream.
REFRESH_MARGIN_SECONDS = 30


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


class OAuthBroker:
    def __init__(self, store: Store, vault: Vault, http: httpx.AsyncClient, public_url: str):
        self._store = store
        self._vault = vault
        self._http = http
        self._redirect_uri = f"{public_url.rstrip('/')}/v1/connections/callback"
        # Per-connection refresh lock: one refresh flight per connection per
        # process (a lost race across instances only costs a redundant refresh).
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    # -- authorization-code + PKCE flow --------------------------------------------------

    def start(self, app: ProviderApp, tenant_id: str, user_id: str) -> dict[str, str]:
        """Build the provider authorize URL; the state is single-use and binds
        {tenant, user, app, PKCE verifier} server-side."""
        state = secrets.token_urlsafe(24)
        verifier = _b64url(secrets.token_bytes(48))
        self._store.put_oauth_state(
            _sha256_hex(state),
            {
                "tenantId": tenant_id,
                "userId": user_id,
                "providerAppId": app.id,
                "codeVerifier": verifier,
                "expiresAt": (_now() + timedelta(seconds=STATE_TTL_SECONDS)).isoformat(),
            },
        )
        query = urlencode(
            {
                "response_type": "code",
                "client_id": app.clientId,
                "redirect_uri": self._redirect_uri,
                "scope": " ".join(app.scopes),
                "state": state,
                "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in app.authorizeUrl else "?"
        return {"authorizeUrl": f"{app.authorizeUrl}{separator}{query}", "state": state}

    async def complete(self, state: str, code: str) -> Connection:
        """Callback half: consume the single-use state, exchange the code, seal
        the token set, and upsert the {tenant, user, app} connection."""
        doc = self._store.consume_oauth_state(_sha256_hex(state))
        if doc is None:
            raise ToolgateError(ErrorCodes.VALIDATION, "unknown or already-used state")
        if datetime.fromisoformat(doc["expiresAt"]) < _now():
            raise ToolgateError(ErrorCodes.VALIDATION, "authorization flow expired; restart it")
        app = self._store.get_provider_app(doc["providerAppId"])
        if app is None:
            raise ToolgateError(ErrorCodes.NOT_FOUND, "provider app no longer exists")

        tokens = await self._token_request(
            app,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
                "code_verifier": doc["codeVerifier"],
            },
        )
        connection_id = self._store.connection_id(doc["tenantId"], app.id, doc["userId"])
        now = _now().isoformat()
        existing = self._store.get_connection(connection_id)
        access_ref = f"sec_{connection_id}_at"
        refresh_ref = f"sec_{connection_id}_rt"
        self._store.put_secret(access_ref, self._vault.seal(tokens["access_token"]))
        has_refresh = bool(tokens.get("refresh_token"))
        if has_refresh:
            self._store.put_secret(refresh_ref, self._vault.seal(tokens["refresh_token"]))
        connection = Connection(
            id=connection_id,
            tenantId=doc["tenantId"],
            userId=doc["userId"],
            providerAppId=app.id,
            accessTokenRef=access_ref,
            refreshTokenRef=refresh_ref if has_refresh else None,
            expiresAt=self._expiry(tokens),
            scopes=app.scopes,
            status="active",
            createdAt=existing.createdAt if existing else now,
            updatedAt=now,
        )
        self._store.put_connection(connection)
        return connection

    # -- gate-time token resolution -------------------------------------------------------

    async def access_token(self, connection: Connection) -> str:
        """Live access token for a connection, refreshing transparently when
        it is at/near expiry. The token never reaches the agent or the audit."""
        if not self._near_expiry(connection):
            return self._open_secret(connection.accessTokenRef)
        async with self._locks[connection.id]:
            # Another coroutine may have refreshed while we waited.
            current = self._store.get_connection(connection.id)
            if current is None or current.status != "active":
                raise ToolgateError(ErrorCodes.CONNECTION_REQUIRED, "connection was revoked")
            if not self._near_expiry(current):
                return self._open_secret(current.accessTokenRef)
            return await self._refresh(current)

    async def _refresh(self, connection: Connection) -> str:
        if not connection.refreshTokenRef:
            raise ToolgateError(
                ErrorCodes.CONNECTION_FAILED,
                "access token expired and the provider issued no refresh token — reconnect",
            )
        app = self._store.get_provider_app(connection.providerAppId)
        if app is None:
            raise ToolgateError(ErrorCodes.CONNECTION_FAILED, "provider app no longer exists")
        refresh_token = self._open_secret(connection.refreshTokenRef)
        tokens = await self._token_request(
            app, {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )
        self._store.put_secret(
            connection.accessTokenRef, self._vault.seal(tokens["access_token"])
        )
        if tokens.get("refresh_token"):
            # Provider rotated the refresh token; keep only the new one.
            self._store.put_secret(
                connection.refreshTokenRef, self._vault.seal(tokens["refresh_token"])
            )
        connection.expiresAt = self._expiry(tokens)
        connection.updatedAt = _now().isoformat()
        self._store.put_connection(connection)
        return tokens["access_token"]

    def revoke(self, connection: Connection) -> None:
        """Instant: sealed tokens are deleted; the next gated call refuses,
        independent of provider-side token lifetimes."""
        connection.status = "revoked"
        connection.updatedAt = _now().isoformat()
        self._store.put_connection(connection)
        self._store.delete_secret(connection.accessTokenRef)
        if connection.refreshTokenRef:
            self._store.delete_secret(connection.refreshTokenRef)

    # -- internals ------------------------------------------------------------------------

    async def _token_request(self, app: ProviderApp, form: dict[str, str]) -> dict[str, Any]:
        sealed = self._store.get_secret(app.clientSecretRef)
        if sealed is None:
            raise ToolgateError(ErrorCodes.CONNECTION_FAILED, "provider app secret missing")
        data = {**form, "client_id": app.clientId, "client_secret": self._vault.open(sealed)}
        try:
            res = await self._http.post(app.tokenUrl, data=data)
        except httpx.HTTPError as err:
            raise ToolgateError(
                ErrorCodes.CONNECTION_FAILED, f"provider token endpoint unreachable: {err}"
            ) from err
        try:
            body = res.json()
        except ValueError:
            body = {}
        if res.status_code >= 400 or "access_token" not in body:
            reason = body.get("error", f"http {res.status_code}")
            raise ToolgateError(
                ErrorCodes.CONNECTION_FAILED, f"provider token request failed: {reason}"
            )
        return body

    def _open_secret(self, ref: str) -> str:
        sealed = self._store.get_secret(ref)
        if sealed is None:
            raise ToolgateError(
                ErrorCodes.CONNECTION_REQUIRED, "connection tokens were revoked — reconnect"
            )
        return self._vault.open(sealed)

    @staticmethod
    def _near_expiry(connection: Connection) -> bool:
        expires = datetime.fromisoformat(connection.expiresAt)
        return (expires - _now()).total_seconds() <= REFRESH_MARGIN_SECONDS

    @staticmethod
    def _expiry(tokens: dict[str, Any]) -> str:
        return (_now() + timedelta(seconds=int(tokens.get("expires_in", 3600)))).isoformat()


def new_provider_app_id() -> str:
    return new_id("evt").replace("evt_", "oap_")
