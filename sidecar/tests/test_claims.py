# sidecar/tests/test_claims.py
from envoy.service.auth.v3.external_auth_pb2 import CheckRequest
from google.protobuf.struct_pb2 import Struct

from openapl_sidecar.claims import claims_from_check, struct_to_dict

NS = "envoy.filters.http.jwt_authn"


def _req(ns, payload):
    req = CheckRequest()
    s = Struct()
    s.update(payload)
    req.attributes.metadata_context.filter_metadata[ns].CopyFrom(s)
    return req


def test_struct_ints():
    s = Struct()
    s.update({"iat": 900, "act": {"sub": "a"}, "l": [1, 2.5, {"n": 3}], "b": True, "z": None})
    d = struct_to_dict(s)
    assert d == {"iat": 900, "act": {"sub": "a"}, "l": [1, 2.5, {"n": 3}], "b": True, "z": None}
    assert type(d["iat"]) is int
    assert type(d["l"][0]) is int and type(d["l"][1]) is float
    assert type(d["l"][2]["n"]) is int


def test_claims_default_path():
    req = _req(NS, {"jwt_payload": {"iat": 5, "email": "a@b"}})
    assert claims_from_check(req, NS, "jwt_payload") == {"iat": 5, "email": "a@b"}


def test_claims_custom_namespace_without_field():
    req = _req("my.ns", {"iat": 7})
    assert claims_from_check(req, "my.ns", None) == {"iat": 7}


def test_claims_missing_returns_none():
    assert claims_from_check(CheckRequest(), NS, "jwt_payload") is None
    assert claims_from_check(_req(NS, {"other": {"a": 1}}), NS, "jwt_payload") is None
    assert claims_from_check(_req(NS, {"jwt_payload": "str"}), NS, "jwt_payload") is None
