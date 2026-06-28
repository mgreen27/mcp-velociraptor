import os
from pathlib import Path


def load_environment() -> None:
    """Load dotenv values without overriding existing environment."""
    repo_root = Path(__file__).resolve().parent
    configured_env = os.environ.get("VELOCIRAPTOR_ENV_FILE", "").strip()

    if configured_env:
        configured_path = Path(configured_env).expanduser()
        if not configured_path.is_absolute():
            configured_path = repo_root / configured_path
        _load_env_file(configured_path)

    _load_env_file(repo_root / ".env")


def _load_env_file(env_path: Path) -> None:
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        _load_simple_env(env_path)
        return

    load_dotenv(env_path, override=False)


def _load_simple_env(env_path: Path) -> None:
    for line in env_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value
