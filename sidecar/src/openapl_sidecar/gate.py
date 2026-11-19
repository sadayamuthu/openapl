# sidecar/src/openapl_sidecar/gate.py
import dataclasses
import time
from collections.abc import Callable
from dataclasses import dataclass

from openapl.authorizer import Authorizer
from openapl.chain import ChainError, chain_from_list, request_from_claims
from openapl.decision_log import DecisionLog
from openapl.model import Decision

from openapl_sidecar.bindings import BindingError, Bindings, map_call
from openapl_sidecar.mcp import McpParseError, tool_calls


@dataclass(frozen=True)
class GateResult:
    decision: str
    reasons: tuple[str, ...]
    approvers: tuple[str, ...]
    decision_ids: tuple[str, ...]


def _deny(reason: str) -> GateResult:
    return GateResult("DENY", (reason,), (), ())


class Gate:
    def __init__(self, authorizer: Authorizer, bindings: Bindings, log: DecisionLog | None,
                 dev_mode: bool, clock: Callable[[], int] = lambda: int(time.time())):
        self.authorizer = authorizer
        self.bindings = bindings
        self.log = log
        self.dev_mode = dev_mode
        self.clock = clock

    def decide(self, claims: dict | None, action: str, resource: str, attributes: dict,
               dev_chain: list[str] | None = None) -> Decision:
        ps = self.authorizer.ps
        c = claims or {}
        req = request_from_claims(c, ps, action, resource, attributes, self.clock())
        if self.dev_mode and dev_chain is not None:
            try:
                chain = chain_from_list(dev_chain, ps, c)
            except ChainError:
                chain = ()
            req = dataclasses.replace(req, chain=chain, dev_mode=True)
        elif self.dev_mode:
            req = dataclasses.replace(req, dev_mode=True)
        d = self.authorizer.decide(req)
        if self.log is not None:
            try:
                self.log.append(d)
            except OSError:
                d = dataclasses.replace(d, decision="DENY", approvers=(),
                                        reasons=d.reasons + ("decision log write failed",))
        return d

    def check_mcp(self, http_method: str, body: bytes, claims: dict | None,
                  dev_chain: list[str] | None = None) -> GateResult:
        if http_method in ("GET", "DELETE"):
            return GateResult("ALLOW", (), (), ())
        if http_method != "POST":
            return _deny(f"http method {http_method} not allowed")
        try:
            calls = tool_calls(body, self.bindings.passthrough_methods)
            mapped = [map_call(self.bindings, c.wire_name, c.arguments) for c in calls]
        except (McpParseError, BindingError) as e:
            return _deny(str(e))
        decisions = [self.decide(claims, a, r, attrs, dev_chain) for a, r, attrs in mapped]
        if any(d.decision == "DENY" for d in decisions):
            verdict = "DENY"
        elif any(d.decision == "REQUIRE_APPROVAL" for d in decisions):
            verdict = "REQUIRE_APPROVAL"
        else:
            verdict = "ALLOW"
        approvers: list[str] = []
        if verdict == "REQUIRE_APPROVAL":
            for d in decisions:
                for a in d.approvers:
                    if a not in approvers:
                        approvers.append(a)
        return GateResult(verdict, tuple(r for d in decisions for r in d.reasons),
                          tuple(approvers), tuple(d.decision_id for d in decisions))
