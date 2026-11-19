# sidecar/src/openapl_sidecar/authzen.py
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from openapl_sidecar.config import Settings
from openapl_sidecar.gate import Gate

MAX_BODY = 1024 * 1024
MAX_BATCH = 100
SEMANTICS = ("execute_all", "deny_on_first_deny", "permit_on_first_permit")
EVALUATION_PATH = "/access/v1/evaluation"
EVALUATIONS_PATH = "/access/v1/evaluations"
WELL_KNOWN = "/.well-known/authzen-configuration"


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _bad(message: str) -> RequestError:
    return RequestError(400, message)


def _obj(value, name: str) -> dict:
    if not isinstance(value, dict):
        raise _bad(f"{name} must be an object")
    return value


def _nonempty(obj: dict, key: str, name: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str) or not v:
        raise _bad(f"{name} is required and must be a non-empty string")
    return v


def _openapl_context(d) -> dict:
    return {"decision": d.decision, "approvers": list(d.approvers),
            "reasons": list(d.reasons), "decision_id": d.decision_id}


def _evaluate(gate: Gate, ev: dict) -> dict:
    """Map one AuthZEN evaluation, decide, and return the response object.

    Raises RequestError for malformed input."""
    subject = _obj(ev.get("subject"), "subject")
    sid = _nonempty(subject, "id", "subject.id")
    _nonempty(subject, "type", "subject.type")
    action = _nonempty(_obj(ev.get("action"), "action"), "name", "action.name")
    res = _obj(ev.get("resource"), "resource")
    rtype = _nonempty(res, "type", "resource.type")
    rid = _nonempty(res, "id", "resource.id")
    ctx = ev.get("context", {})
    ctx = _obj(ctx if ctx is not None else {}, "context")
    props = res.get("properties")
    props = _obj(props, "resource.properties") if props is not None else {}
    extra = ctx.get("attributes")
    extra = _obj(extra, "context.attributes") if extra is not None else {}
    for k in extra:
        if k in props:
            raise _bad(f"attribute '{k}' given twice")
    attributes = {**props, **extra}
    if "claims" in ctx and ctx["claims"] is not None:
        claims = _obj(ctx["claims"], "context.claims")
        given = [claims[k] for k in ("email", "sub") if k in claims]
        if given and sid not in given:
            raise _bad("subject.id does not match claims")
    else:
        claims = {"sub": sid}
    chain = None
    if gate.dev_mode and "chain" in ctx:
        chain = ctx["chain"]
        if not isinstance(chain, list) or not all(isinstance(c, str) for c in chain):
            raise _bad("context.chain must be a list of strings")
    d = gate.decide(claims, action, f"{rtype}/{rid}", attributes, chain)
    return {"decision": d.decision == "ALLOW", "context": {"openapl": _openapl_context(d)}}


def _internal_error_single() -> dict:
    return {"decision": False,
            "context": {"openapl": {"decision": "DENY", "approvers": [],
                                    "reasons": ["internal error"], "decision_id": ""}}}


def _item_error(status: int, message: str) -> dict:
    return {"decision": False, "context": {"error": {"status": status, "message": message}}}


def _single(gate: Gate, ev: dict) -> dict:
    try:
        return _evaluate(gate, ev)
    except RequestError:
        raise
    except Exception:
        return _internal_error_single()


def _batch(gate: Gate, body: dict) -> dict:
    items = body["evaluations"]
    if not isinstance(items, list):
        raise _bad("evaluations must be an array")
    if len(items) > MAX_BATCH:
        raise _bad(f"evaluations may hold at most {MAX_BATCH} items")
    options = body.get("options")
    options = _obj(options, "options") if options is not None else {}
    semantic = options.get("evaluations_semantic", "execute_all")
    if semantic not in SEMANTICS:
        raise _bad(f"unknown evaluations_semantic {semantic!r}")
    defaults = {k: body[k] for k in ("subject", "action", "resource", "context") if k in body}
    out = []
    for item in items:
        if not isinstance(item, dict):
            result = _item_error(400, "evaluation must be an object")
        else:
            try:
                result = _evaluate(gate, {**defaults, **item})
            except RequestError as e:
                result = _item_error(e.status, e.message)
            except Exception:
                result = _item_error(500, "internal error")
        out.append(result)
        if (semantic == "deny_on_first_deny" and result["decision"] is False) or (
                semantic == "permit_on_first_permit" and result["decision"] is True):
            break
    return {"evaluations": out}


def make_authzen_server(gate: Gate, settings: Settings,
                        port: int | None = None) -> ThreadingHTTPServer:
    token = settings.pdp_token
    base = settings.pdp_base_url

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            pass

        def _send(self, status: int, body, extra: dict | None = None):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            rid = self.headers.get("X-Request-ID")
            if rid is not None:
                self.send_header("X-Request-ID", rid)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if token is None:
                return True
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode())

        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
            elif self.path == WELL_KNOWN and base:
                self._send(200, {
                    "policy_decision_point": base,
                    "access_evaluation_endpoint": base + EVALUATION_PATH,
                    "access_evaluations_endpoint": base + EVALUATIONS_PATH,
                })
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                self._post()
            except RequestError as e:
                self._send(e.status, {"error": e.message})
            except Exception:
                self.close_connection = True
                self._send(500, {"error": "internal error"})

        def _post(self):
            if self.path not in (EVALUATION_PATH, EVALUATIONS_PATH):
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                raise _bad("Content-Type must be application/json")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise _bad("invalid Content-Length") from None
            if length < 0:
                raise _bad("invalid Content-Length")
            if length > MAX_BODY:
                self.close_connection = True
                if length <= 8 * MAX_BODY:  # drain so the client can read the 413
                    self.rfile.read(length)
                raise RequestError(413, "request body too large")
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                raise _bad("invalid JSON") from None
            body = _obj(body, "request body")
            if self.path == EVALUATIONS_PATH and body.get("evaluations"):
                self._send(200, _batch(gate, body))
            else:
                self._send(200, _single(gate, body))

    return ThreadingHTTPServer((settings.bind_host, settings.authzen_port if port is None
                                else port), Handler)
