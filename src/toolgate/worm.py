"""WORM (write-once) retention exports of the audit bundle (#12).

Two providers: a filesystem directory (write-once enforced with O_EXCL +
read-only mode) and S3 with Object Lock (COMPLIANCE mode — not deletable until
the retention date, even by the bucket owner). Every export appends a SHA-256
manifest entry to an export index, so the set of exports is itself auditable.
Schedule via cron/systemd timer: `toolgate audit worm-export ...`."""

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_RETENTION_DAYS = 183  # >= 6 months


def _bundle_text(bundle: dict[str, Any]) -> tuple[str, str, str]:
    """(filename, canonical text, sha256)."""
    seq = max((c["seq"] for c in bundle.get("checkpoints", [])), default=0)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    text = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    return (
        f"toolgate-audit-{ts}-seq{seq}.json",
        text,
        hashlib.sha256(text.encode()).hexdigest(),
    )


def _manifest_entry(
    bundle: dict[str, Any], name: str, digest: str, retention_days: int
) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "file": name,
        "sha256": digest,
        "records": len(bundle.get("records", [])),
        "checkpoints": len(bundle.get("checkpoints", [])),
        "anchored": sum(1 for c in bundle.get("checkpoints", []) if c.get("anchor")),
        "exportedAt": now.isoformat(),
        "retainUntil": (now + timedelta(days=retention_days)).isoformat(),
    }


def export_bundle_fs(
    bundle: dict[str, Any],
    directory: Path,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> dict[str, Any]:
    """Write-once export to a directory. O_EXCL refuses to overwrite an existing
    export; the file lands read-only. Pair with immutable storage (e.g. a WORM
    mount or snapshotted volume) for hard retention."""
    directory.mkdir(parents=True, exist_ok=True)
    name, text, digest = _bundle_text(bundle)
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o444)
    entry = _manifest_entry(bundle, name, digest, retention_days)
    with open(directory / "manifest.jsonl", "a") as manifest:
        manifest.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def export_bundle_s3(
    bundle: dict[str, Any],
    bucket: str,
    prefix: str = "toolgate-audit/",
    retention_days: int = DEFAULT_RETENTION_DAYS,
    s3_client: Any | None = None,
) -> dict[str, Any]:
    """Export under S3 Object Lock (COMPLIANCE): the object cannot be deleted or
    overwritten until the retention date, even by the bucket owner. The bucket
    must be created with Object Lock enabled."""
    if s3_client is None:
        try:
            import boto3
        except ImportError as err:
            raise RuntimeError(
                "boto3 is required for S3 WORM export: pip install 'toolgate-io[s3]'"
            ) from err
        s3_client = boto3.client("s3")
    name, text, digest = _bundle_text(bundle)
    entry = _manifest_entry(bundle, name, digest, retention_days)
    retain_until = datetime.fromisoformat(entry["retainUntil"])
    common = {
        "Bucket": bucket,
        "ObjectLockMode": "COMPLIANCE",
        "ObjectLockRetainUntilDate": retain_until,
    }
    s3_client.put_object(
        Key=f"{prefix}{name}", Body=text.encode(), ContentType="application/json", **common
    )
    s3_client.put_object(
        Key=f"{prefix}manifests/{name}.manifest.json",
        Body=(json.dumps(entry, sort_keys=True) + "\n").encode(),
        ContentType="application/json",
        **common,
    )
    entry["bucket"] = bucket
    entry["key"] = f"{prefix}{name}"
    return entry
