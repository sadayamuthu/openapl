# demo/agentgateway/probe/probe.py
"""Recording ext_authz probe: appends each CheckRequest as a JSON line, always allows."""
import json
import threading
from concurrent import futures

import grpc
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from google.protobuf.json_format import MessageToDict
from google.rpc import code_pb2, status_pb2

LOG = "/out/checks.jsonl"
_lock = threading.Lock()


class Probe(external_auth_pb2_grpc.AuthorizationServicer):
    def Check(self, request, context):
        http = request.attributes.request.http
        rec = {
            "method": http.method,
            "path": http.path,
            "headers": dict(http.headers),
            "body": http.body,
            "raw_body_len": len(http.raw_body),
            "raw_body": http.raw_body.decode("utf-8", "replace"),
            "metadata_context": {
                k: MessageToDict(v) for k, v in request.attributes.metadata_context.filter_metadata.items()
            },
        }
        with _lock, open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        return external_auth_pb2.CheckResponse(
            status=status_pb2.Status(code=code_pb2.OK), ok_response=external_auth_pb2.OkHttpResponse())


def main() -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(Probe(), server)
    server.add_insecure_port("0.0.0.0:9000")
    server.start()
    print("probe listening on :9000", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
