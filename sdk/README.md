# openapl (Python SDK)

Reference engine and CLI for the [OpenAPL v0.1 specification](../spec/SPEC.md).
Pure Python. `Authorizer.decide` does no network or file I/O, never reads
the clock and never raises: any error becomes `DENY` with a reason.

```bash
pip install -e '.[dev]'
pytest -q
```

## Library API

### Load a policy set

```python
from openapl import Authorizer

authz = Authorizer.from_dir("policies/")                        # every *.apl.yaml
authz = Authorizer.from_dir("policies/", "directory.json")      # with {"active": [owners]}
```

`from_dir` raises `openapl.PolicyLoadError` (a `ValueError`) on any
schema or load error. `Authorizer(policy_set)` accepts a `PolicySet` from
`openapl.load_policy_dir`.

### Build a request from verified claims

In production the gateway verifies the JWT and passes its claims.
`request_from_claims` builds the chain from nested RFC 8693 `act` claims
and reads `openapl_purpose`, `openapl_task_id`, `openapl_approvals` and
`iat` from the claims only:

```python
import time
from openapl.chain import request_from_claims

claims = {
    "sub": "alice", "email": "alice@acme.com", "groups": ["support-staff"],
    "openapl_purpose": "customer-refund", "openapl_task_id": "t1",
    "act": {"sub": "refund-agent",
            "act": {"sub": "spiffe://acme.com/agents/support-agent"}},
}
request = request_from_claims(
    claims, authz.ps, "payments.refund", "order/123",
    {"order_id": "123", "amount": 150, "account_status": "open"},
    now=int(time.time()),
)
decision = authz.decide(request)
print(decision.decision, decision.reasons)   # ALLOW ()
```

A malformed chain or approval claim gives an empty chain, which is denied.

`chain_from_claims(claims, policy_set)` returns just the chain, a tuple of
`Link`. It raises `openapl.chain.ChainError` if the claims have neither
`email` nor `sub`, if an actor is malformed, or if `act` nests deeper
than 32 levels. Unresolvable actors become `unknown:<sub>` links.

### Build a request directly

```python
from openapl import Link, Request

request = Request(
    chain=(
        Link("user:alice@acme.com", "human", {"groups": ["support-staff"]}),
        Link("support-agent", "agent", {}),
        Link("refund-agent", "agent", {}),
    ),
    action="payments.refund",
    resource="order/123",
    attributes={"order_id": "123", "amount": 150, "account_status": "open"},
    purpose="customer-refund",
    task_id="t1",
    now=int(time.time()),      # required: now <= 0 is denied
)
```

`Request` fields: `chain`, `action`, `resource`, `attributes`, `purpose`,
`task_id`, `token_iat`, `now`, `approvals` (a tuple of `Approval`) and
`dev_mode`. Human links must have ids `user:<id>`.

### The decision

`Decision` is frozen. `decision` is `"ALLOW"`, `"DENY"` or
`"REQUIRE_APPROVAL"`; it also carries `approvers`, `chain`, `reasons`,
`matched`, `grants`, `policies`, `controls`, `dev_mode`, `decision_id`
and `timestamp`. `decision.to_dict()` gives the JSON record
(SPEC §9.1). `openapl.decision_log.DecisionLog(path).append(decision)`
appends it to a JSON Lines log.

`openapl.approvals.attributes_hash(attributes)` computes the
`attributes_hash` an approval item must carry.

## CLI

`openapl validate | decide | explain | inventory | evidence`. See the
[repository README](../README.md) and `openapl <command> --help`.
