import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolgate.cli.main import app
from toolgate.demo import CRM_SECRET, EMAIL_SECRET, make_upstreams, serve_in_thread
from toolgate.server import create_app, create_app_context

GATE_PORT = 8497
UPSTREAM_PORT = 8498
GATE_URL = f"http://127.0.0.1:{GATE_PORT}"

runner = CliRunner()


class Env:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        ctx = create_app_context(db_path=":memory:", public_url=GATE_URL)
        self.servers = [
            serve_in_thread(create_app(ctx), GATE_PORT),
            serve_in_thread(make_upstreams(), UPSTREAM_PORT),
        ]
        os.environ["TOOLGATE_URL"] = GATE_URL
        os.environ["TOOLGATE_ADMIN_KEY"] = ctx.config.admin_key
        os.environ["TOOLGATE_CONFIG"] = str(tmp / "config.json")

        self.key_file = tmp / "agent-key.json"
        self.tenant = self.run_json("keys", "generate", "--out", str(self.key_file)) and None
        self.tenant = self.run_json("tenants", "create", "Acme")["id"]
        self.user = self.run_json(
            "users", "create", "-t", self.tenant, "--name", "Sam", "--email", "sam@acme.com"
        )["id"]
        self.agent = self.run_json(
            "agents", "register", "-t", self.tenant, "--name", "assistant",
            "--key", str(self.key_file),
        )["id"]

        self.run_json(
            "upstreams", "add", "-t", self.tenant, "--name", "crm",
            "--base-url", f"http://127.0.0.1:{UPSTREAM_PORT}/crm",
            "--mode", "bearer", "--secret", CRM_SECRET,
            "--tool", "read_contact", "--tool", "delete_contact:1:se",
        )
        self.run_json(
            "upstreams", "add", "-t", self.tenant, "--name", "email",
            "--base-url", f"http://127.0.0.1:{UPSTREAM_PORT}/email",
            "--mode", "header", "--header-name", "X-Api-Key", "--secret", EMAIL_SECRET,
            "--tool", "send_email:2:se",
        )

        rules = tmp / "rules.json"
        rules.write_text(json.dumps([
            {"id": "never-delete", "effect": "deny", "match": {"tool": "delete_*"}},
            {"id": "external-email", "effect": "require_approval",
             "match": {"tool": "send_email",
                       "where": [{"path": "to", "op": "matches", "value": "@(?!acme\\.com)"}]}},
            {"id": "allow-rest", "effect": "allow", "match": {}},
        ]))
        self.policy = self.run_json(
            "policies", "create", "-t", self.tenant, "--name", "default",
            "--rules-file", str(rules),
        )["id"]
        self.grant = self.run_json(
            "grants", "create", "-t", self.tenant, "--user", self.user, "--agent", self.agent,
            "--policy", self.policy, "--budget", "10", "--authz", "crm:*", "--authz", "email:*",
        )["id"]

    def run(self, *args: str, expect: int = 0) -> str:
        result = runner.invoke(app, list(args))
        assert result.exit_code == expect, f"toolgate {' '.join(args)}\n{result.output}"
        return result.output

    def run_json(self, *args: str, expect: int = 0):
        out = self.run("--json", *args, expect=expect)
        return json.loads(out)

    def close(self) -> None:
        for s in self.servers:
            s.should_exit = True
        for var in ("TOOLGATE_URL", "TOOLGATE_ADMIN_KEY", "TOOLGATE_CONFIG"):
            os.environ.pop(var, None)


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Env:
    e = Env(tmp_path_factory.mktemp("cli"))
    yield e
    e.close()


def test_lists_show_created_entities(env: Env) -> None:
    agents = env.run_json("agents", "list", "-t", env.tenant)
    assert [a["id"] for a in agents] == [env.agent]
    upstreams = env.run_json("upstreams", "list", "-t", env.tenant)
    assert {u["name"] for u in upstreams} == {"crm", "email"}
    assert "sealed" not in json.dumps(upstreams)  # no secret material in responses
    assert CRM_SECRET not in json.dumps(upstreams)


def test_dev_call_allowed_and_budget_visible(env: Env) -> None:
    out = env.run_json(
        "dev", "call", "crm", "read_contact",
        "--grant", env.grant, "--key", str(env.key_file), "--args", '{"contactId": "c-01"}',
    )
    assert out["status"] == "executed"
    assert out["result"]["contact"]["id"] == "c-01"

    grant = env.run_json("grants", "show", env.grant)
    assert grant["budget"]["spentUnits"] == 1


def test_dev_call_denied_by_policy(env: Env) -> None:
    result = runner.invoke(app, [
        "--json", "dev", "call", "crm", "delete_contact",
        "--grant", env.grant, "--key", str(env.key_file),
    ])
    assert result.exit_code == 1
    assert "TG_DENIED" in result.output


def test_approval_flow_via_cli(env: Env) -> None:
    parked = env.run_json(
        "dev", "call", "email", "send_email",
        "--grant", env.grant, "--key", str(env.key_file),
        "--args", '{"to": "cfo@globex.com", "subject": "hi"}',
    )
    assert parked["status"] == "pending_approval"
    approval_id = parked["approval_id"]

    pending = env.run_json("approvals", "list", "-t", env.tenant, "--status", "pending")
    assert approval_id in [a["id"] for a in pending]

    decided = env.run_json("approvals", "approve", approval_id, "--by", env.user)
    assert decided["status"] == "approved"

    executed = env.run_json(
        "dev", "execute", approval_id, "--grant", env.grant, "--key", str(env.key_file)
    )
    assert executed["status"] == "executed"
    assert executed["result"]["sent"] is True


def test_audit_verify_server_and_offline(env: Env) -> None:
    verify = env.run_json("audit", "verify")
    assert verify["valid"] is True and verify["length"] >= 3

    export_file = env.tmp / "audit.json"
    exported = env.run_json("audit", "export", "--out", str(export_file))
    assert exported["records"] == verify["length"]
    assert len(exported["sha256"]) == 64

    offline = env.run_json("audit", "verify", "--file", str(export_file))
    assert offline["valid"] is True

    # Tamper with the export: offline verification must name the breakpoint.
    records = json.loads(export_file.read_text())
    records[0]["decision"]["reason"] = "cover-up"
    export_file.write_text(json.dumps(records))
    broken = env.run_json("audit", "verify", "--file", str(export_file), expect=2)
    assert broken["valid"] is False and broken["broken_at_seq"] == 1


def test_revoked_grant_blocks_dev_call(env: Env) -> None:
    env.run_json("grants", "revoke", env.grant, "--yes")
    result = runner.invoke(app, [
        "--json", "dev", "call", "crm", "read_contact",
        "--grant", env.grant, "--key", str(env.key_file),
    ])
    assert result.exit_code == 1
    assert "TG_REVOKED" in result.output
