"""Transparency-log anchoring sink (#12). Publishes checkpoints to a
Rekor-compatible log (hashedrekord submission shape) and persists the returned
inclusion evidence with the checkpoint, so exported bundles are verifiable by a
party that trusts only the log's pinned public key.

Anchoring runs off the request path (worker loop) and is best-effort per
checkpoint — but persistent failure is loud: a consecutive-failure counter
feeds /healthz and a log line fires when it crosses the degraded threshold.
"""

import base64
import time
from typing import Any

import httpx

from toolgate.core import Checkpoint, checkpoint_anchor_digest

from .store import Store

DEGRADED_AFTER_FAILURES = 3
RETRY_HOLDOFF_SECONDS = 30.0


class RekorSink:
    """Client for a Rekor-compatible log: POST {url}/api/v1/log/entries with a
    hashedrekord entry over the checkpoint's canonical signed bytes."""

    def __init__(self, url: str, http: httpx.Client | None = None) -> None:
        self._url = url.rstrip("/")
        self._http = http or httpx.Client(timeout=10.0)

    def anchor(
        self, checkpoint: Checkpoint, *, public_key_pem: str | None = None
    ) -> dict[str, Any]:
        digest = checkpoint_anchor_digest(checkpoint)
        entry: dict[str, Any] = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": digest}},
                "signature": {
                    "content": checkpoint.sig,
                    "publicKey": {
                        "content": base64.b64encode((public_key_pem or "").encode()).decode()
                    },
                },
            },
        }
        res = self._http.post(f"{self._url}/api/v1/log/entries", json=entry)
        res.raise_for_status()
        body = res.json()
        # Rekor keys the response by entry uuid.
        uuid, record = next(iter(body.items()))
        proof = record["verification"]["inclusionProof"]
        return {
            "logId": record["logID"],
            "logIndex": proof["logIndex"],
            "uuid": uuid,
            "rootHash": proof["rootHash"],
            "treeSize": proof["treeSize"],
            "hashes": proof["hashes"],
            "signedRoot": proof["signedRoot"],
        }


class AnchorWorker:
    """Drives unanchored checkpoints to the log; tracks failure state for
    operator visibility. process_pending() is called from the server worker
    thread (and directly in tests)."""

    def __init__(self, store: Store, sink: RekorSink) -> None:
        self._store = store
        self._sink = sink
        self.consecutive_failures = 0
        self.last_error: str | None = None
        self._holdoff_until = 0.0

    @property
    def degraded(self) -> bool:
        return self.consecutive_failures >= DEGRADED_AFTER_FAILURES

    def process_pending(self, *, force: bool = False) -> int:
        """Anchor every stored checkpoint that lacks evidence; returns how many
        were anchored. After a failure, backs off briefly instead of hammering."""
        if not force and time.monotonic() < self._holdoff_until:
            return 0
        anchored = 0
        for checkpoint in self._store.list_checkpoints():
            if checkpoint.anchor:
                continue
            try:
                checkpoint.anchor = self._sink.anchor(checkpoint)
            except (httpx.HTTPError, KeyError, ValueError, StopIteration) as err:
                self.consecutive_failures += 1
                self.last_error = str(err)[:200]
                self._holdoff_until = time.monotonic() + RETRY_HOLDOFF_SECONDS
                if self.degraded:
                    print(
                        f"[toolgate] ANCHORING DEGRADED: {self.consecutive_failures} "
                        f"consecutive checkpoint anchor failures (last: {self.last_error})"
                    )
                return anchored
            self._store.put_checkpoint(checkpoint)
            anchored += 1
            self.consecutive_failures = 0
            self.last_error = None
        return anchored

    def status(self, total: int, anchored: int) -> dict[str, Any]:
        return {
            "enabled": True,
            "anchored": anchored,
            "total": total,
            "consecutive_failures": self.consecutive_failures,
            "degraded": self.degraded,
            **({"last_error": self.last_error} if self.last_error else {}),
        }
