# sidecar/tests/test_config.py
import pytest

from openapl_sidecar.config import ConfigError, settings_from_env

BASE = {"OPENAPL_POLICY_DIR": "/p", "OPENAPL_PDP_TOKEN": "t"}


def test_token_required_outside_dev_mode():
    with pytest.raises(ConfigError, match="OPENAPL_PDP_TOKEN is required unless OPENAPL_DEV_MODE=1"):
        settings_from_env({"OPENAPL_POLICY_DIR": "/p"})


def test_policy_dir_required():
    with pytest.raises(ConfigError, match="OPENAPL_POLICY_DIR"):
        settings_from_env({"OPENAPL_PDP_TOKEN": "t"})


def test_defaults():
    s = settings_from_env(BASE)
    assert (s.authzen_port, s.extauthz_port, s.bind_host, s.dev_mode) == (8081, 9000, "0.0.0.0", False)
    assert (s.claims_namespace, s.claims_field) == ("envoy.filters.http.jwt_authn", "jwt_payload")
    assert (s.bindings_path, s.decision_log, s.pdp_base_url) == (None, None, None)


def test_dev_mode_needs_no_token():
    s = settings_from_env({"OPENAPL_POLICY_DIR": "/p", "OPENAPL_DEV_MODE": "1"})
    assert s.pdp_token is None and s.dev_mode is True


def test_overrides():
    s = settings_from_env({**BASE, "OPENAPL_BINDINGS": "b.yaml", "OPENAPL_DECISION_LOG": "d.jsonl",
                           "OPENAPL_BIND_HOST": "127.0.0.1", "OPENAPL_AUTHZEN_PORT": "1",
                           "OPENAPL_EXTAUTHZ_PORT": "65535", "OPENAPL_PDP_BASE_URL": "https://pdp.example"})
    assert (s.bindings_path, s.decision_log, s.bind_host) == ("b.yaml", "d.jsonl", "127.0.0.1")
    assert (s.authzen_port, s.extauthz_port, s.pdp_base_url) == (1, 65535, "https://pdp.example")


def test_claims_metadata_split():
    assert settings_from_env({**BASE, "OPENAPL_CLAIMS_METADATA": "my.ns"}).claims_field is None
    s = settings_from_env({**BASE, "OPENAPL_CLAIMS_METADATA": "my.ns/a/b"})
    assert (s.claims_namespace, s.claims_field) == ("my.ns", "a/b")


@pytest.mark.parametrize("k,v", [("OPENAPL_AUTHZEN_PORT", "0"), ("OPENAPL_AUTHZEN_PORT", "65536"),
                                 ("OPENAPL_EXTAUTHZ_PORT", "x"), ("OPENAPL_DEV_MODE", "yes"),
                                 ("OPENAPL_PDP_BASE_URL", "http://pdp")])
def test_bad_values(k, v):
    with pytest.raises(ConfigError):
        settings_from_env({**BASE, k: v})


def test_directory_snapshot_env():
    assert settings_from_env(BASE).directory_snapshot is None
    s = settings_from_env({**BASE, "OPENAPL_DIRECTORY_SNAPSHOT": "/d.json"})
    assert s.directory_snapshot == "/d.json"
