# sidecar/tests/test_server.py
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from openapl_sidecar import __version__
from openapl_sidecar.server import main

DATA = Path(__file__).resolve().parent / "data"


def env(monkeypatch, **kw):
    for k in list(os.environ):
        if k.startswith("OPENAPL_"):
            monkeypatch.delenv(k)
    for k, v in kw.items():
        monkeypatch.setenv(k, v)


def test_exit_2_on_missing_token(monkeypatch, refund_dir, capsys):
    env(monkeypatch, OPENAPL_POLICY_DIR=str(refund_dir))
    assert main(["serve"]) == 2
    assert "OPENAPL_PDP_TOKEN is required" in capsys.readouterr().err


def test_exit_2_on_bad_policy_dir(monkeypatch, tmp_path, capsys):
    env(monkeypatch, OPENAPL_POLICY_DIR=str(tmp_path / "nope"), OPENAPL_PDP_TOKEN="t")
    assert main(["serve"]) == 2
    assert capsys.readouterr().err.startswith("openapl-sidecar: ")


def test_exit_2_on_bad_bindings(monkeypatch, refund_dir, tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 99\n")
    env(monkeypatch, OPENAPL_POLICY_DIR=str(refund_dir), OPENAPL_PDP_TOKEN="t",
        OPENAPL_BINDINGS=str(bad))
    assert main(["serve"]) == 2
    assert capsys.readouterr().err.startswith("openapl-sidecar: ")


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"openapl-sidecar {__version__}"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_serve_and_sigterm(refund_dir, bindings_file):
    a, g = free_port(), free_port()
    e = {**os.environ, "OPENAPL_POLICY_DIR": str(refund_dir), "OPENAPL_BINDINGS": bindings_file,
         "OPENAPL_PDP_TOKEN": "t", "OPENAPL_BIND_HOST": "127.0.0.1",
         "OPENAPL_AUTHZEN_PORT": str(a), "OPENAPL_EXTAUTHZ_PORT": str(g)}
    p = subprocess.Popen([sys.executable, "-m", "openapl_sidecar.server", "serve"], env=e,
                         stderr=subprocess.PIPE)
    try:
        base = f"http://127.0.0.1:{a}"
        deadline = time.time() + 10
        while True:
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=1) as r:
                    if r.status == 200:
                        break
            except (urllib.error.URLError, ConnectionError):
                pass
            assert p.poll() is None and time.time() < deadline, "sidecar did not become healthy"
            time.sleep(0.1)
        req = urllib.request.Request(
            base + "/access/v1/evaluation", data=(DATA / "authzen-allow.json").read_bytes(),
            headers={"Authorization": "Bearer t", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert json.loads(r.read())["decision"] is True
        p.send_signal(signal.SIGTERM)
        assert p.wait(timeout=10) == 0
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        p.stderr.close()


def test_exit_2_when_extauthz_port_in_use(monkeypatch, refund_dir, capsys):
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        env(monkeypatch, OPENAPL_POLICY_DIR=str(refund_dir), OPENAPL_PDP_TOKEN="t",
            OPENAPL_BIND_HOST="127.0.0.1", OPENAPL_AUTHZEN_PORT=str(free_port()),
            OPENAPL_EXTAUTHZ_PORT=str(held.getsockname()[1]))
        assert main(["serve"]) == 2
    assert capsys.readouterr().err.startswith("openapl-sidecar: ")


def test_exit_2_on_unwritable_decision_log(monkeypatch, refund_dir, tmp_path, capsys):
    path = tmp_path / "no-such-dir" / "log.jsonl"
    env(monkeypatch, OPENAPL_POLICY_DIR=str(refund_dir), OPENAPL_PDP_TOKEN="t",
        OPENAPL_DECISION_LOG=str(path))
    assert main(["serve"]) == 2
    assert f"cannot write decision log {path}" in capsys.readouterr().err
