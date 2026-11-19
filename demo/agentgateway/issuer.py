# demo/agentgateway/issuer.py
"""Demo JWT issuer: RS256 keys, JWKS, and tokens carrying design 4.4 claims."""
import argparse
import base64
import json
import os
import sys
import time

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openapl.approvals import attributes_hash

ISSUER = "https://issuer.demo.openapl.local"
AUDIENCE = "agentgateway-demo"
KID = "demo-1"


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_keys(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    path = os.path.join(out_dir, "private.pem")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)
    nums = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": _b64(nums.n), "e": _b64(nums.e)}
    with open(os.path.join(out_dir, "jwks.json"), "w", encoding="utf-8") as f:
        json.dump({"keys": [jwk]}, f, indent=2)


def approval_item(*, entitlement_id: str, approver: str, action: str, resource: str,
                  attributes: dict, origin: str, caller: str, exp: int) -> dict:
    return {
        "entitlement_id": entitlement_id, "approver": approver, "action": action,
        "resource": resource, "attributes_hash": attributes_hash(attributes),
        "origin": origin, "caller": caller, "exp": exp,
    }


def mint(out_dir: str, *, email: str, groups: list[str], actors: list[str],
         purpose: str | None = "customer-refund", task_id: str | None = "t1",
         approvals: list[dict] | None = None, now: int | None = None, lifetime: int = 600) -> str:
    iat = int(time.time()) if now is None else now
    claims: dict = {"iss": ISSUER, "aud": AUDIENCE, "iat": iat, "exp": iat + lifetime,
                    "email": email, "groups": groups}
    if purpose is not None:
        claims["openapl_purpose"] = purpose
    if task_id is not None:
        claims["openapl_task_id"] = task_id
    if approvals is not None:
        claims["openapl_approvals"] = approvals
    act: dict | None = None
    for sub in actors:  # first hop innermost; current caller ends up outermost
        act = {"sub": sub} if act is None else {"sub": sub, "act": act}
    if act is not None:
        claims["act"] = act
    with open(os.path.join(out_dir, "private.pem"), "rb") as f:
        pem = f.read()
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": KID})


def token_from_spec(out_dir: str, spec: dict, now: int | None = None) -> str:
    """Mint a token from a scenarios.yaml `token` block (mint kwargs; `approval` adds one approval_item)."""
    spec = dict(spec)
    iat = int(time.time()) if now is None else now
    approvals = spec.pop("approvals", None)
    appr = spec.pop("approval", None)
    if appr is not None:
        appr = dict(appr)
        appr.setdefault("exp", iat + 600)
        approvals = (approvals or []) + [approval_item(**appr)]
    return mint(out_dir, approvals=approvals, now=iat, **spec)


def load_scenarios(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)["scenarios"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="issuer.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keys", help="generate private.pem and jwks.json")
    k.add_argument("out_dir")
    t = sub.add_parser("token", help="print the JWT for a scenario's token block")
    t.add_argument("--scenario", required=True)
    t.add_argument("--scenarios", required=True)
    t.add_argument("--out-dir", default="out")
    args = ap.parse_args(argv)
    if args.cmd == "keys":
        make_keys(args.out_dir)
    elif args.cmd == "token":
        rows = {r["id"]: r for r in load_scenarios(args.scenarios)}
        if args.scenario not in rows:
            print(f"issuer.py: unknown scenario {args.scenario!r}", file=sys.stderr)
            return 2
        if not rows[args.scenario].get("token"):
            print(f"issuer.py: scenario {args.scenario!r} has no token", file=sys.stderr)
            return 2
        print(token_from_spec(args.out_dir, rows[args.scenario]["token"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
