"""Approval notification channels: `toolgate channels ...` and `toolgate slack ...`.

Channel secrets (Slack bot token / signing secret, SMTP password) are sent to
the server exactly once and sealed into the vault; list output only ever shows
refs. Secrets are prompted with hidden input when not passed as options."""

from typing import Annotated

import typer

from .shared import _table, channels_app, client, emit, slack_app


@channels_app.command("list")
def channels_list(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/channels", tenantId=tenant)
    rows = [[c["id"], c["config"]["type"], c["name"], c["status"]] for c in data]
    emit(data, _table("channels", ["id", "type", "name", "status"], rows))


@channels_app.command("add-webhook")
def channels_add_webhook(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    url: Annotated[str, typer.Option("--url", help="HTTPS endpoint receiving signed payloads.")],
) -> None:
    data = client().post(
        "/v1/control/channels",
        {"tenantId": tenant, "name": name, "type": "webhook", "url": url},
    )
    emit(data, f"[green]webhook channel created[/] {data['id']} -> {url}")


@channels_app.command("add-slack")
def channels_add_slack(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    channel: Annotated[str, typer.Option("--channel", help="Slack channel id (C…).")],
    bot_token: Annotated[
        str, typer.Option("--bot-token", prompt=True, hide_input=True)
    ],
    signing_secret: Annotated[
        str, typer.Option("--signing-secret", prompt=True, hide_input=True)
    ],
) -> None:
    data = client().post(
        "/v1/control/channels",
        {
            "tenantId": tenant,
            "name": name,
            "type": "slack",
            "slackChannel": channel,
            "botToken": bot_token,
            "signingSecret": signing_secret,
        },
    )
    emit(
        data,
        f"[green]slack channel created[/] {data['id']} -> {channel}\n"
        f"point the app's interactivity request URL at <public-url>/v1/hooks/slack "
        f"and bind approvers with: toolgate slack bind",
    )


@channels_app.command("add-email")
def channels_add_email(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    smtp_host: Annotated[str, typer.Option("--smtp-host")],
    from_address: Annotated[str, typer.Option("--from-address")],
    recipient: Annotated[
        list[str],
        typer.Option("--recipient", help="email:operator_id — repeatable."),
    ],
    smtp_port: Annotated[int, typer.Option("--smtp-port")] = 587,
    smtp_user: Annotated[str | None, typer.Option("--smtp-user")] = None,
    smtp_password: Annotated[
        str | None, typer.Option("--smtp-password", hide_input=True)
    ] = None,
    no_tls: Annotated[bool, typer.Option("--no-tls", help="Disable STARTTLS.")] = False,
) -> None:
    recipients = []
    for spec in recipient:
        email, _, operator = spec.partition(":")
        if not operator:
            raise typer.BadParameter(f"--recipient must be email:operator_id, got {spec!r}")
        recipients.append({"email": email, "operatorId": operator})
    data = client().post(
        "/v1/control/channels",
        {
            "tenantId": tenant,
            "name": name,
            "type": "email",
            "smtpHost": smtp_host,
            "smtpPort": smtp_port,
            "smtpUser": smtp_user,
            "smtpPassword": smtp_password,
            "fromAddress": from_address,
            "useTls": not no_tls,
            "recipients": recipients,
        },
    )
    emit(data, f"[green]email channel created[/] {data['id']} ({len(recipients)} recipients)")


@channels_app.command("delete")
def channels_delete(channel_id: str) -> None:
    data = client().delete(f"/v1/control/channels/{channel_id}")
    emit(data, f"[yellow]channel deleted[/] {channel_id}")


@channels_app.command("deliveries")
def channels_deliveries(approval_id: str) -> None:
    data = client().get(f"/v1/control/approvals/{approval_id}/deliveries")
    rows = [
        [d["id"], d["channelType"], d["event"], d["status"], str(d["attempts"]),
         (d.get("lastError") or "")[:40]]
        for d in data
    ]
    emit(
        data,
        _table(
            f"deliveries for {approval_id}",
            ["id", "channel", "event", "status", "attempts", "last error"],
            rows,
        ),
    )


@slack_app.command("bind")
def slack_bind(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    slack_user: Annotated[str, typer.Option("--slack-user", help="Slack user id (U…).")],
    operator: Annotated[str, typer.Option("--operator", help="Operator id (op_…).")],
) -> None:
    data = client().post(
        "/v1/control/slack-bindings",
        {"tenantId": tenant, "slackUserId": slack_user, "operatorId": operator},
    )
    emit(data, f"[green]bound[/] slack {slack_user} -> operator {operator}")


@slack_app.command("bindings")
def slack_bindings(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/slack-bindings", tenantId=tenant)
    rows = [[b["slackUserId"], b["operatorId"], b["createdAt"][:19]] for b in data]
    emit(data, _table("slack bindings", ["slack user", "operator", "created"], rows))
