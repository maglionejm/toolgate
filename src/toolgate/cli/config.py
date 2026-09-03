import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


def config_path() -> Path:
    return Path(os.environ.get("TOOLGATE_CONFIG", "~/.toolgate/config.json")).expanduser()


@dataclass(frozen=True)
class Profile:
    url: str
    admin_key: str


def load_profiles() -> dict[str, dict[str, str]]:
    path = config_path()
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _write_0600(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` created already at mode 0600 — no default-umask
    (0644) window a concurrent reader could exploit and nothing left world-readable
    if the process crashes mid-write."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        # Tighten even if the file already existed with looser perms (the mode
        # argument to os.open only applies when the file is created).
        os.fchmod(fh.fileno(), 0o600)
        fh.write(text)


def save_profile(name: str, url: str, admin_key: str) -> Path:
    path = config_path()
    profiles = load_profiles()
    profiles[name] = {"url": url.rstrip("/"), "admin_key": admin_key}
    # Private parent dir; an already-existing dir keeps its own mode.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_0600(path, json.dumps(profiles, indent=2) + "\n")
    return path


def resolve(profile: str | None) -> Profile:
    """Environment wins (CI/scripting); otherwise the named or default profile."""
    env_url = os.environ.get("TOOLGATE_URL")
    env_key = os.environ.get("TOOLGATE_ADMIN_KEY")
    if env_url and env_key:
        return Profile(url=env_url.rstrip("/"), admin_key=env_key)
    if env_url or env_key:
        # Exactly one half set: do NOT silently mix a staging URL with the stored
        # (prod) key, or vice versa. Ignore the partial override and warn loudly.
        which = "TOOLGATE_URL" if env_url else "TOOLGATE_ADMIN_KEY"
        print(
            f"warning: only {which} is set; both TOOLGATE_URL and TOOLGATE_ADMIN_KEY are "
            "required to override — ignoring it and using the stored profile.",
            file=sys.stderr,
        )

    profiles = load_profiles()
    name = profile or "default"
    if name not in profiles:
        raise LookupError(
            f"no profile '{name}' — run `toolgate init` or set TOOLGATE_URL and TOOLGATE_ADMIN_KEY"
        )
    entry = profiles[name]
    return Profile(url=entry["url"], admin_key=entry["admin_key"])
