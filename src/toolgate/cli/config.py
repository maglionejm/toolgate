import json
import os
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


def save_profile(name: str, url: str, admin_key: str) -> Path:
    path = config_path()
    profiles = load_profiles()
    profiles[name] = {"url": url.rstrip("/"), "admin_key": admin_key}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profiles, indent=2) + "\n")
    path.chmod(0o600)
    return path


def resolve(profile: str | None) -> Profile:
    """Environment wins (CI/scripting); otherwise the named or default profile."""
    env_url = os.environ.get("TOOLGATE_URL")
    env_key = os.environ.get("TOOLGATE_ADMIN_KEY")
    if env_url and env_key:
        return Profile(url=env_url.rstrip("/"), admin_key=env_key)

    profiles = load_profiles()
    name = profile or "default"
    if name not in profiles:
        raise LookupError(
            f"no profile '{name}' — run `toolgate init` or set TOOLGATE_URL and TOOLGATE_ADMIN_KEY"
        )
    entry = profiles[name]
    return Profile(url=entry["url"], admin_key=entry["admin_key"])
