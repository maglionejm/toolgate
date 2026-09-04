"""Adversary: races the gate. Guarantee: exactly-once for budget and
approval execution under concurrency."""

import anyio
import httpx

from toolgate.core import sign_pop_proof

PUBLIC_URL = "http://testserver"


def test_last_budget_unit_single_winner(target):
    grant = target.grant(budget=1)
    token = target.token(grant)

    async def run():
        transport = httpx.ASGITransport(app=target.app)
        async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client:
            import json as _json

            async def one(i: int):
                path = "/v1/gate/call/web"
                body = _json.dumps({"tool": "browse", "args": {"i": i}}).encode()
                proof = sign_pop_proof(
                    target.agent_keys.private_jwk, htm="POST",
                    htu=f"{PUBLIC_URL}{path}", access_token=token, body=body,
                )
                return await client.post(
                    path,
                    headers={
                        "authorization": f"Bearer {token}",
                        "x-toolgate-proof": proof,
                        "content-type": "application/json",
                    },
                    content=body,
                )

            results = []

            async with anyio.create_task_group() as tg:
                async def collect(i):
                    results.append(await one(i))

                for i in range(4):
                    tg.start_soon(collect, i)
            return results

    results = anyio.run(run)
    executed = sum(1 for r in results if r.status_code == 200)
    assert executed == 1
    assert target.ctx.store.get_grant(grant).budget.spentUnits == 1
