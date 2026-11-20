# sidecar/src/openapl_sidecar/server.py
import argparse
import logging
import os
import signal
import sys
import threading

from openapl import Authorizer, PolicyLoadError
from openapl.decision_log import DecisionLog

from . import __version__
from .authzen import make_authzen_server
from .bindings import BindingError, load_bindings
from .config import ConfigError, settings_from_env
from .extauthz import make_extauthz_server
from .gate import Gate


def _serve() -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        settings = settings_from_env(os.environ)
        if not os.path.isdir(settings.policy_dir):
            raise ConfigError(f"OPENAPL_POLICY_DIR is not a directory: {settings.policy_dir}")
        authorizer = Authorizer.from_dir(settings.policy_dir)
        bindings = load_bindings(settings.bindings_path)
        log = DecisionLog(settings.decision_log) if settings.decision_log else None
        if settings.decision_log:
            try:
                with open(settings.decision_log, "a", encoding="utf-8"):
                    pass
            except OSError as e:
                raise ConfigError(f"cannot write decision log {settings.decision_log}: {e}") from None
    except (ConfigError, PolicyLoadError, BindingError) as e:
        print(f"openapl-sidecar: {e}", file=sys.stderr)
        return 2

    gate = Gate(authorizer, bindings, log, dev_mode=settings.dev_mode)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    http_server = None
    try:
        http_server = make_authzen_server(gate, settings)
        grpc_server, grpc_port = make_extauthz_server(gate, settings)
    except (OSError, RuntimeError) as e:
        if http_server is not None:
            http_server.server_close()
        print(f"openapl-sidecar: cannot bind listener: {e}", file=sys.stderr)
        return 2
    if grpc_port == 0:
        http_server.server_close()
        print("openapl-sidecar: cannot bind ext_authz port", file=sys.stderr)
        return 2

    if settings.dev_mode:
        print("WARNING: dev mode", file=sys.stderr)
    grpc_server.start()
    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()
    print(f"authzen listening on {settings.bind_host}:{http_server.server_address[1]}",
          file=sys.stderr, flush=True)
    print(f"ext_authz listening on {settings.bind_host}:{grpc_port}", file=sys.stderr, flush=True)

    stop.wait()
    http_server.shutdown()
    http_server.server_close()
    grpc_server.stop(grace=5).wait()
    thread.join()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openapl-sidecar")
    parser.add_argument("--version", action="version", version=f"openapl-sidecar {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the AuthZEN and ext_authz listeners")
    parser.parse_args(argv)
    return _serve()


if __name__ == "__main__":
    sys.exit(main())
