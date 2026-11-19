# sidecar/src/openapl_sidecar/config.py
from collections.abc import Mapping
from dataclasses import dataclass


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    policy_dir: str
    bindings_path: str | None
    decision_log: str | None
    pdp_token: str | None
    dev_mode: bool
    bind_host: str
    authzen_port: int
    extauthz_port: int
    claims_namespace: str
    claims_field: str | None
    pdp_base_url: str | None
    directory_snapshot: str | None = None


def _port(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        port = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer in 1-65535, got {raw!r}") from None
    if not 1 <= port <= 65535:
        raise ConfigError(f"{name} must be an integer in 1-65535, got {raw!r}")
    return port


def settings_from_env(env: Mapping[str, str]) -> Settings:
    policy_dir = env.get("OPENAPL_POLICY_DIR")
    if not policy_dir:
        raise ConfigError("OPENAPL_POLICY_DIR is required")
    dev = env.get("OPENAPL_DEV_MODE", "0")
    if dev not in ("0", "1"):
        raise ConfigError(f"OPENAPL_DEV_MODE must be 0 or 1, got {dev!r}")
    dev_mode = dev == "1"
    token = env.get("OPENAPL_PDP_TOKEN") or None
    if token is None and not dev_mode:
        raise ConfigError("OPENAPL_PDP_TOKEN is required unless OPENAPL_DEV_MODE=1")
    base_url = env.get("OPENAPL_PDP_BASE_URL") or None
    if base_url is not None and not base_url.startswith("https://"):
        raise ConfigError("OPENAPL_PDP_BASE_URL must start with https://")
    namespace, sep, field = env.get(
        "OPENAPL_CLAIMS_METADATA", "envoy.filters.http.jwt_authn/jwt_payload"
    ).partition("/")
    if not namespace:
        raise ConfigError("OPENAPL_CLAIMS_METADATA must start with a namespace")
    return Settings(
        policy_dir=policy_dir,
        bindings_path=env.get("OPENAPL_BINDINGS") or None,
        decision_log=env.get("OPENAPL_DECISION_LOG") or None,
        pdp_token=token,
        dev_mode=dev_mode,
        bind_host=env.get("OPENAPL_BIND_HOST", "0.0.0.0"),
        authzen_port=_port(env, "OPENAPL_AUTHZEN_PORT", 8081),
        extauthz_port=_port(env, "OPENAPL_EXTAUTHZ_PORT", 9000),
        claims_namespace=namespace,
        claims_field=(field or None) if sep else None,
        pdp_base_url=base_url,
        directory_snapshot=env.get("OPENAPL_DIRECTORY_SNAPSHOT") or None,
    )
