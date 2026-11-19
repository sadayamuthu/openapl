# sidecar/src/openapl_sidecar/extauthz.py
import json
from concurrent import futures

import grpc
from envoy.config.core.v3.base_pb2 import HeaderValue, HeaderValueOption
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.type.v3.http_status_pb2 import HttpStatus, StatusCode
from google.protobuf.struct_pb2 import Struct
from google.rpc.status_pb2 import Status

from openapl_sidecar.claims import claims_from_check
from openapl_sidecar.config import Settings
from openapl_sidecar.gate import Gate, GateResult

CHAIN_HEADER = "x-openapl-chain"


def _denied(r: GateResult) -> external_auth_pb2.CheckResponse:
    first = r.decision_ids[0] if r.decision_ids else ""
    body = json.dumps({
        "decision": r.decision,
        "reasons": list(r.reasons),
        "approvers": list(r.approvers),
        "decision_id": first,
        "decision_ids": list(r.decision_ids),
    }, ensure_ascii=True)
    headers = [
        ("x-openapl-decision", r.decision),
        ("x-openapl-decision-id", first),
        ("content-type", "application/json"),
    ]
    return external_auth_pb2.CheckResponse(
        status=Status(code=7),
        denied_response=external_auth_pb2.DeniedHttpResponse(
            status=HttpStatus(code=StatusCode.Forbidden),
            headers=[HeaderValueOption(header=HeaderValue(key=k, value=v)) for k, v in headers],
            body=body,
        ),
    )


def _allowed(r: GateResult) -> external_auth_pb2.CheckResponse:
    md = Struct()
    md.update({"openapl": {"decision": "ALLOW", "decision_ids": list(r.decision_ids)}})
    return external_auth_pb2.CheckResponse(
        status=Status(code=0),
        ok_response=external_auth_pb2.OkHttpResponse(),
        dynamic_metadata=md,
    )


class OpenAplAuthorization(external_auth_pb2_grpc.AuthorizationServicer):
    def __init__(self, gate: Gate, settings: Settings):
        self.gate = gate
        self.settings = settings

    def Check(self, request, context):
        try:
            http = request.attributes.request.http
            body = bytes(http.raw_body) or http.body.encode("utf-8")
            claims = claims_from_check(request, self.settings.claims_namespace,
                                       self.settings.claims_field)
            chain = None
            if self.gate.dev_mode:
                raw = http.headers.get(CHAIN_HEADER)
                if raw is not None:
                    chain = [p.strip() for p in raw.split(",") if p.strip()]
            r = self.gate.check_mcp(http.method, body, claims, chain)
            return _allowed(r) if r.decision == "ALLOW" else _denied(r)
        except Exception:
            return _denied(GateResult("DENY", ("internal error",), (), ()))


def make_extauthz_server(gate: Gate, settings: Settings,
                         port: int | None = None) -> tuple[grpc.Server, int]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        OpenAplAuthorization(gate, settings), server)
    p = port if port is not None else settings.extauthz_port
    bound = server.add_insecure_port(f"{settings.bind_host}:{p}")
    return server, bound
