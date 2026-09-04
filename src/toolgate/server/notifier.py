"""Approval push notifications (#13): webhook, Slack, and email magic links.

Parked approvals fan out to every active channel of the tenant as delivery
records; a retry loop attempts them with exponential backoff. Webhook payloads
are signed with the gate key (detached JWS, kid included) so receivers verify
against the published JWKS — the same signing discipline as the audit chain.
Slack messages render the exact args and update when the approval is decided
elsewhere; email decisions ride single-use magic links bound to the approval's
args hash.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import smtplib
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any

import httpx

from toolgate.core import (
    ApprovalRequest,
    Delivery,
    EmailChannelConfig,
    NotificationChannel,
    SlackChannelConfig,
    hash_args,
    new_id,
    sign_detached_jws,
)

from .store import Store
from .vault import Vault

MAX_ATTEMPTS = 6
BACKOFF_BASE_SECONDS = 2
SLACK_API = "https://slack.com/api"

# Events that fan out per channel type. Email only announces parked approvals —
# its "cancel" is structural: a decided approval makes every magic link inert.
_EVENTS_BY_TYPE = {
    "webhook": ("parked", "decided", "expired"),
    "slack": ("parked", "decided", "expired"),
    "email": ("parked",),
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Notifier:
    """Creates delivery records on approval transitions and drives them to a
    terminal state. Network and SMTP effects are injectable for tests."""

    def __init__(
        self,
        *,
        store: Store,
        vault: Vault,
        public_url: str,
        signer: Callable[[], tuple[dict[str, Any], str]],
        http: httpx.Client | None = None,
        mailer: Callable[..., None] | None = None,
    ) -> None:
        self._store = store
        self._vault = vault
        self._public_url = public_url.rstrip("/")
        # () -> (gate private JWK, kid); resolved per call so key rotation
        # is picked up without rebuilding the notifier.
        self._signer = signer
        self._http = http or httpx.Client(timeout=10.0)
        self._mailer = mailer or self._smtp_send
        # Tests set inline=True for synchronous, deterministic processing.
        self.inline = False

    # -- fan-out ------------------------------------------------------------------

    def fanout(self, approval: ApprovalRequest, event: str) -> list[Delivery]:
        """Create one pending delivery per active channel that handles `event`."""
        now = _now()
        deliveries = []
        for channel in self._store.list_channels(approval.tenantId):
            if channel.status != "active":
                continue
            if event not in _EVENTS_BY_TYPE[channel.config.type]:
                continue
            delivery = Delivery(
                id=new_id("dlv"),
                tenantId=approval.tenantId,
                channelId=channel.id,
                channelType=channel.config.type,
                approvalId=approval.id,
                event=event,  # type: ignore[arg-type]
                status="pending",
                nextAttemptAt=now,
                createdAt=now,
                updatedAt=now,
            )
            self._store.put_delivery(delivery)
            deliveries.append(delivery)
        if deliveries:
            self._kick()
        return deliveries

    def _kick(self) -> None:
        if self.inline:
            self.process_due()
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop (CLI paths): the background worker will pick it up
        loop.run_in_executor(None, self.process_due)

    # -- delivery loop ------------------------------------------------------------

    def process_due(self, now_ms: int | None = None) -> int:
        """Attempt every due pending delivery once; returns how many were tried."""
        due = self._store.due_deliveries(now_ms)
        for delivery in due:
            self._attempt(delivery)
        return len(due)

    def _attempt(self, delivery: Delivery) -> None:
        channel = self._store.get_channel(delivery.channelId)
        approval = self._store.get_approval(delivery.approvalId)
        if channel is None or channel.status != "active" or approval is None:
            self._finish(delivery, "failed", error="channel or approval gone")
            return
        try:
            meta = self._deliver(channel, approval, delivery)
        except Exception as err:  # noqa: BLE001 - any delivery error means retry
            self._retry(delivery, str(err))
            return
        delivery.meta = meta or delivery.meta
        self._finish(delivery, "delivered")

    def _deliver(
        self, channel: NotificationChannel, approval: ApprovalRequest, delivery: Delivery
    ) -> dict[str, Any] | None:
        config = channel.config
        if config.type == "webhook":
            self._send_webhook(config.url, approval, delivery)
            return None
        if config.type == "slack":
            return self._send_slack(config, approval, delivery)
        self._send_email(config, approval)
        return None

    def _retry(self, delivery: Delivery, error: str) -> None:
        delivery.attempts += 1
        delivery.lastError = error[:300]
        delivery.updatedAt = _now()
        if delivery.attempts >= MAX_ATTEMPTS:
            delivery.status = "failed"
        else:
            backoff = BACKOFF_BASE_SECONDS**delivery.attempts
            delivery.nextAttemptAt = (
                datetime.now(UTC) + timedelta(seconds=backoff)
            ).isoformat()
        self._store.put_delivery(delivery)

    def _finish(self, delivery: Delivery, status: str, *, error: str | None = None) -> None:
        delivery.status = status  # type: ignore[assignment]
        delivery.lastError = error or delivery.lastError
        delivery.updatedAt = _now()
        self._store.put_delivery(delivery)

    # -- webhook ------------------------------------------------------------------

    def _send_webhook(
        self, url: str, approval: ApprovalRequest, delivery: Delivery
    ) -> None:
        payload = json.dumps(
            {
                "deliveryId": delivery.id,
                "event": f"approval.{delivery.event}",
                "approval": approval.model_dump(mode="json", exclude_none=True),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        private_jwk, kid = self._signer()
        res = self._http.post(
            url,
            content=payload,
            headers={
                "content-type": "application/json",
                # Detached JWS over the exact body bytes; verify against /v1/keys.
                "x-toolgate-signature": sign_detached_jws(payload, private_jwk, kid=kid),
                "x-toolgate-kid": kid,
                # Stable per-delivery id: receivers dedupe retries on it.
                "x-toolgate-delivery": delivery.id,
            },
        )
        res.raise_for_status()

    # -- slack --------------------------------------------------------------------

    def _slack_token(self, config: SlackChannelConfig) -> str:
        sealed = self._store.get_secret(config.botTokenRef)
        if sealed is None:
            raise RuntimeError("slack bot token missing from vault")
        return self._vault.open(sealed)

    def _send_slack(
        self, config: SlackChannelConfig, approval: ApprovalRequest, delivery: Delivery
    ) -> dict[str, Any] | None:
        if delivery.event == "parked":
            return self._slack_post(config, approval)
        return self._slack_update(config, approval, delivery)

    def _slack_post(
        self, config: SlackChannelConfig, approval: ApprovalRequest
    ) -> dict[str, Any]:
        res = self._http.post(
            f"{SLACK_API}/chat.postMessage",
            headers={"authorization": f"Bearer {self._slack_token(config)}"},
            json={
                "channel": config.channel,
                "text": f"Approval requested: {approval.upstream}.{approval.tool}",
                "blocks": _slack_blocks(approval, actionable=True),
            },
        )
        res.raise_for_status()
        body = res.json()
        if not body.get("ok"):
            raise RuntimeError(f"slack error: {body.get('error', 'unknown')}")
        return {"ts": body["ts"], "channel": body.get("channel", config.channel)}

    def _slack_update(
        self, config: SlackChannelConfig, approval: ApprovalRequest, delivery: Delivery
    ) -> dict[str, Any] | None:
        # The original parked delivery holds the message ts to update.
        parked = [
            d
            for d in self._store.deliveries_for_approval(approval.id)
            if d.channelId == delivery.channelId and d.event == "parked"
        ]
        posted = next((d for d in parked if d.status == "delivered" and d.meta), None)
        if posted is None:
            if parked and all(d.status == "failed" for d in parked):
                return None  # nothing was ever posted; nothing to update
            raise RuntimeError("parked slack message not delivered yet")
        assert posted.meta is not None
        res = self._http.post(
            f"{SLACK_API}/chat.update",
            headers={"authorization": f"Bearer {self._slack_token(config)}"},
            json={
                "channel": posted.meta["channel"],
                "ts": posted.meta["ts"],
                "text": f"Approval {approval.status}: {approval.upstream}.{approval.tool}",
                # Buttons removed: the decision happened, the surface deactivates.
                "blocks": _slack_blocks(approval, actionable=False),
            },
        )
        res.raise_for_status()
        body = res.json()
        if not body.get("ok"):
            raise RuntimeError(f"slack error: {body.get('error', 'unknown')}")
        return posted.meta

    # -- email --------------------------------------------------------------------

    def _send_email(self, config: EmailChannelConfig, approval: ApprovalRequest) -> None:
        password = None
        if config.smtpPasswordRef:
            sealed = self._store.get_secret(config.smtpPasswordRef)
            password = self._vault.open(sealed) if sealed else None
        for recipient in config.recipients:
            links = {
                decision: self._mint_link(approval, decision, recipient.operatorId)
                for decision in ("approve", "deny")
            }
            body = (
                f"An agent call is parked for approval.\n\n"
                f"Tool: {approval.upstream}.{approval.tool}\n"
                f"Args: {json.dumps(approval.args, indent=2, sort_keys=True)}\n"
                f"Requested: {approval.requestedAt}\nExpires: {approval.expiresAt}\n\n"
                f"Approve: {links['approve']}\nDeny:    {links['deny']}\n\n"
                f"Links are single-use, bound to these exact arguments, and die "
                f"with the approval."
            )
            self._mailer(
                host=config.smtpHost,
                port=config.smtpPort,
                user=config.smtpUser,
                password=password,
                use_tls=config.useTls,
                from_address=config.fromAddress,
                to=recipient.email,
                subject=f"[toolgate] approval needed: {approval.upstream}.{approval.tool}",
                body=body,
            )

    def _mint_link(self, approval: ApprovalRequest, decision: str, operator_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self._store.put_link_token(
            hashlib.sha256(token.encode()).hexdigest(),
            {
                "approvalId": approval.id,
                "tenantId": approval.tenantId,
                "decision": decision,
                "argsHash": hash_args(approval.args),
                "operatorId": operator_id,
                # Never outlives the approval itself.
                "expiresAt": approval.expiresAt,
            },
        )
        return f"{self._public_url}/v1/approvals/link/{token}"

    @staticmethod
    def _smtp_send(
        *,
        host: str,
        port: int,
        user: str | None,
        password: str | None,
        use_tls: bool,
        from_address: str,
        to: str,
        subject: str,
        body: str,
    ) -> None:
        msg = EmailMessage()
        msg["From"] = from_address
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)


def _slack_blocks(approval: ApprovalRequest, *, actionable: bool) -> list[dict[str, Any]]:
    """Block Kit rendering of the exact args the human is deciding on."""
    header = (
        f"*Approval requested* — `{approval.upstream}.{approval.tool}`"
        if actionable
        else f"*Approval {approval.status}* — `{approval.upstream}.{approval.tool}`"
    )
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```{json.dumps(approval.args, indent=2, sort_keys=True)}```",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"approval `{approval.id}` · expires {approval.expiresAt}",
                }
            ],
        },
    ]
    if actionable:
        blocks.append(
            {
                "type": "actions",
                "block_id": approval.id,
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "action_id": "tg_approve",
                        "value": approval.id,
                        "text": {"type": "plain_text", "text": "Approve"},
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "action_id": "tg_deny",
                        "value": approval.id,
                        "text": {"type": "plain_text", "text": "Deny"},
                    },
                ],
            }
        )
    return blocks


def verify_slack_signature(
    signing_secret: str, timestamp: str, body: bytes, signature: str
) -> bool:
    """Slack request signing (v0 scheme) with a 5-minute replay window."""
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (TypeError, ValueError):
        return False
    digest = hmac.new(
        signing_secret.encode(), b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"v0={digest}", signature)
