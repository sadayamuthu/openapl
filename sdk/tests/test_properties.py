# sdk/tests/test_properties.py
"""Property-based tests for P1-P5 (design §4.4), over generated policy sets."""
from dataclasses import replace
from fnmatch import fnmatchcase

from hypothesis import assume, event, given, settings
from hypothesis import strategies as st

from openapl.authorizer import Authorizer
from openapl.model import Edge, Entitlement, Link, PolicySet, Principal, Request

ACTIONS = ("a.read", "a.write", "a.delete")
ACTION_PATTERNS = ACTIONS + ("a.*",)
RESOURCES = ("r/1", "r/2")
GRANT_RESOURCES = ("r/1", "r/2", "r/*")
DENY_RESOURCES = GRANT_RESOURCES + ("r/${request.id}",)
GROUPS = ("g1", "g2")
AGENT_IDS = tuple(f"a{i}" for i in range(5))
ORIGIN_ID = "user:h"
SRC = "p.apl.yaml"
WHEN_N = "request.n <= 5"
APPROVAL = "require_approval(role:boss)"
RANK = {"DENY": 0, "REQUIRE_APPROVAL": 1, "ALLOW": 2}

PROPS = settings(max_examples=500, deadline=None)

# -- strategies ---------------------------------------------------------------

_actions = st.lists(st.sampled_from(ACTION_PATTERNS), min_size=1, max_size=3, unique=True).map(tuple)


@st.composite
def _entitlement(draw, idx: int, agents: tuple[str, ...]) -> Entitlement:
    deny = draw(st.integers(0, 5)) == 0
    selectors = ["*", ORIGIN_ID, *(f"group:{g}" for g in GROUPS), *agents]
    when = draw(st.sampled_from([(), (WHEN_N,), (WHEN_N,)]))
    return Entitlement(
        id=f"{'d' if deny else 'e'}{idx}",
        grant_to=tuple(draw(st.lists(st.sampled_from(selectors), min_size=1, max_size=2, unique=True))),
        action=draw(st.sampled_from(ACTION_PATTERNS)),
        resource=draw(st.sampled_from(DENY_RESOURCES if deny else GRANT_RESOURCES)),
        when=when,
        purpose=None,
        expires="never",
        otherwise=None if deny or not when else draw(st.sampled_from([None, APPROVAL, APPROVAL])),
        deny=deny,
        source=SRC,
        source_file=SRC,
    )


@st.composite
def policy_sets(draw) -> PolicySet:
    agents = AGENT_IDS[: draw(st.integers(1, 5))]
    principals = {}
    for a in agents:
        acts_for = draw(st.lists(
            st.builds(Edge, actions=_actions, who=st.sampled_from([f"group:{g}" for g in GROUPS])),
            max_size=2,
        ))
        may_delegate = draw(st.lists(
            st.builds(Edge, actions=_actions, to=st.sampled_from(agents)), max_size=3,
        ))
        principals[a] = Principal(a, "agent", {}, "user:owner", tuple(acts_for), tuple(may_delegate),
                                  SRC, SRC)
    n = draw(st.integers(0, 8))
    entitlements = tuple(draw(_entitlement(i, agents)) for i in range(n))
    return PolicySet(principals, entitlements, draw(st.integers(1, 4)), True, "groups", "roles",
                     {}, None)


_likely = st.sampled_from([True, True, True, False])


@st.composite
def cases(draw) -> tuple[PolicySet, Request]:
    ps = draw(policy_sets())
    groups = list(draw(st.sampled_from([(), ("g1",), ("g2",), ("g1", "g2")])))
    origin = Link(ORIGIN_ID, "human", {"groups": groups})
    action = draw(st.sampled_from(ACTIONS))
    resource = draw(st.sampled_from(RESOURCES))
    agents = draw(st.lists(st.sampled_from(sorted(ps.principals)), min_size=1, max_size=5))
    chain = (origin, *(Link(a, "agent", {}) for a in agents))
    # Purely random edges and grants almost never line up into a non-DENY decision.
    # Plant each needed edge and an origin/caller grant with probability 3/4, so
    # every decision value and every failure mode is common.
    principals = dict(ps.principals)
    for prev, cur in zip(chain, chain[1:]):
        if not draw(_likely):
            continue
        actions = (draw(st.sampled_from([action, "a.*"])),)
        if prev.kind == "human":
            if groups:
                p = principals[cur.principal_id]
                edge = Edge(actions, who=f"group:{draw(st.sampled_from(groups))}")
                principals[p.id] = replace(p, acts_for=(*p.acts_for, edge))
        else:
            p = principals[prev.principal_id]
            principals[p.id] = replace(p, may_delegate=(*p.may_delegate, Edge(actions, to=cur.principal_id)))
    planted = []
    for link in (chain[0], chain[-1]):
        if not draw(_likely):
            continue
        if link.kind == "human":
            selectors = ["*", link.principal_id, *(f"group:{g}" for g in groups)]
        else:
            selectors = ["*", link.principal_id]
        when = draw(st.sampled_from([(), (WHEN_N,)]))
        planted.append(Entitlement(
            id=f"p{len(planted)}",
            grant_to=(draw(st.sampled_from(selectors)),),
            action=draw(st.sampled_from([action, "a.*"])),
            resource=draw(st.sampled_from([resource, "r/*"])),
            when=when, purpose=None, expires="never",
            otherwise=APPROVAL if when else None,
            deny=False, source=SRC, source_file=SRC,
        ))
    entitlements = tuple(draw(st.permutations((*ps.entitlements, *planted))))
    ps = replace(ps, principals=principals, entitlements=entitlements)
    request = Request(chain, action, resource, {"n": draw(st.integers(0, 9)), "id": "1"}, now=1000)
    return ps, request


# -- independent oracles (do not reuse engine code) ----------------------------

def _selects(selector: str, link: Link) -> bool:
    if selector in ("*", link.principal_id):
        return True
    if selector.startswith("group:") and link.kind == "human":
        return selector[len("group:"):] in link.claims.get("groups", [])
    return False


def _when_holds(when: tuple[str, ...], request: Request) -> bool:
    # WHEN_N is the only condition the strategies generate for grants.
    return WHEN_N not in when or request.attributes["n"] <= 5


def _origin_granted(ps: PolicySet, request: Request) -> bool:
    origin = request.chain[0]
    return any(
        not e.deny
        and any(_selects(s, origin) for s in e.grant_to)
        and fnmatchcase(request.action, e.action)
        and fnmatchcase(request.resource, e.resource)
        and _when_holds(e.when, request)
        for e in ps.entitlements
    )


def _deny_scope(e: Entitlement, request: Request) -> bool:
    resource = e.resource.replace("${request.id}", "*")
    return (
        fnmatchcase(request.action, e.action)
        and fnmatchcase(request.resource, resource)
        and any(_selects(s, link) for link in request.chain for s in e.grant_to)
    )


def _edge(ps: PolicySet, prev: Link, cur: Link, action: str) -> bool:
    if prev.kind == "human":
        edges = [e for e in ps.principals[cur.principal_id].acts_for if _selects(e.who, prev)]
    else:
        edges = [e for e in ps.principals[prev.principal_id].may_delegate if e.to == cur.principal_id]
    return any(fnmatchcase(action, a) for e in edges for a in e.actions)


def _decide(ps: PolicySet, request: Request) -> str:
    return Authorizer(ps).decide(request).decision


# -- P1 ------------------------------------------------------------------------

@PROPS
@given(cases(), st.data())
def test_p1_attenuation(case, data):
    # Fixed origin and caller: inserting an agent strictly between them never moves
    # DENY->ALLOW, DENY->REQUIRE_APPROVAL or REQUIRE_APPROVAL->ALLOW.
    # Restated (task-6 report): the insertion splits an edge p(i-1)->p(i) that exists
    # for the action. Without that premise the literal statement is false: a relay
    # can supply a missing direct edge (test_authorizer.py::
    # test_p1_literal_counterexample_relay_supplies_missing_edge).
    ps, request = case
    chain = request.chain
    i = data.draw(st.integers(1, len(chain) - 1), label="insert before index")
    assume(_edge(ps, chain[i - 1], chain[i], request.action))
    x = data.draw(st.sampled_from(sorted(ps.principals)), label="intermediary")
    # Plant x's edges and enough depth with probability 3/4, so the longer chain
    # is often not denied: that is where a violation would show. Both chains are
    # decided under the same (modified) policy set.
    prev, cur = chain[i - 1], chain[i]
    principals = dict(ps.principals)
    if data.draw(_likely, label="plant edge into x"):
        if prev.kind == "human":
            if prev.claims["groups"]:
                g = data.draw(st.sampled_from(prev.claims["groups"]), label="group")
                principals[x] = replace(principals[x], acts_for=(
                    *principals[x].acts_for, Edge((request.action,), who=f"group:{g}")))
        else:
            p = principals[prev.principal_id]
            principals[p.id] = replace(p, may_delegate=(*p.may_delegate, Edge((request.action,), to=x)))
    if data.draw(_likely, label="plant edge out of x"):
        principals[x] = replace(principals[x], may_delegate=(
            *principals[x].may_delegate, Edge((request.action,), to=cur.principal_id)))
    max_depth = ps.max_depth
    if data.draw(_likely, label="raise max_depth"):
        max_depth = max(max_depth, len(chain))
    ps = replace(ps, principals=principals, max_depth=max_depth)
    longer = replace(request, chain=(*chain[:i], Link(x, "agent", {}), *chain[i:]))
    before, after = _decide(ps, request), _decide(ps, longer)
    event(f"{before} -> {after}")
    assert RANK[after] <= RANK[before]


@PROPS
@given(cases())
def test_p1_bounded_by_origin(case):
    ps, request = case
    if _decide(ps, request) == "ALLOW":
        assert _origin_granted(ps, request)


# -- P2 ------------------------------------------------------------------------

@PROPS
@given(cases())
def test_p2_no_confused_deputy(case):
    ps, request = case
    origin = request.chain[0]
    stripped = replace(ps, entitlements=tuple(
        e for e in ps.entitlements if e.deny or not any(_selects(s, origin) for s in e.grant_to)
    ))
    assert _decide(stripped, request) != "ALLOW"


# -- P3 ------------------------------------------------------------------------

@PROPS
@given(cases(), st.data())
def test_p3_deny_overrides(case, data):
    ps, request = case
    link = data.draw(st.sampled_from(request.chain), label="denied link")
    if link.kind == "human":
        selectors = ["*", link.principal_id, *(f"group:{g}" for g in link.claims["groups"])]
    else:
        selectors = ["*", link.principal_id]
    deny = Entitlement(
        id="deny-x",
        grant_to=(data.draw(st.sampled_from(selectors), label="selector"),),
        action=data.draw(st.sampled_from([request.action, "a.*"]), label="action"),
        resource=data.draw(st.sampled_from([request.resource, "r/*", "r/${request.id}"]),
                           label="resource"),
        when=data.draw(st.sampled_from([(), ("request.n >= 0",), ("(((",)]), label="when"),
        purpose=None, expires="never", otherwise=None, deny=True, source=SRC, source_file=SRC,
    )
    pos = data.draw(st.integers(0, len(ps.entitlements)), label="position")
    ents = (*ps.entitlements[:pos], deny, *ps.entitlements[pos:])
    d = Authorizer(replace(ps, entitlements=ents)).decide(request)
    assert d.decision == "DENY"
    assert "deny-x" in d.matched


# -- P4 ------------------------------------------------------------------------

def _record(d) -> dict:
    out = d.to_dict()
    del out["decision_id"]
    return out


@PROPS
@given(cases())
def test_p4_determinism(case):
    ps, request = case
    authorizer = Authorizer(ps)
    first = authorizer.decide(request)
    assert _record(first) == _record(authorizer.decide(request))
    assert _record(first) == _record(Authorizer(ps).decide(request))


# -- P5 ------------------------------------------------------------------------

@PROPS
@given(cases(), st.data())
def test_p5_fail_closed(case, data):
    ps, request = case
    # Broken condition: a grant contributes nothing (no better than absent);
    # a deny whose scope matches a link still denies.
    if ps.entitlements:
        k = data.draw(st.integers(0, len(ps.entitlements) - 1), label="broken entitlement")
        target = ps.entitlements[k]
        broken = replace(ps, entitlements=tuple(
            replace(e, when=("(((",)) if j == k else e for j, e in enumerate(ps.entitlements)
        ))
        d = Authorizer(broken).decide(request)
        assert target.id not in {eid for _, eid in d.grants}
        if target.deny:
            if _deny_scope(target, request):
                assert d.decision == "DENY"
        else:
            absent = replace(ps, entitlements=tuple(e for e in ps.entitlements if e is not target))
            assert RANK[d.decision] <= RANK[_decide(absent, request)]
    # Unknown link: always DENY.
    j = data.draw(st.integers(0, len(request.chain) - 1), label="unknown link")
    old = request.chain[j]
    chain = (*request.chain[:j], Link("unknown:x", old.kind, {}), *request.chain[j + 1:])
    assert _decide(ps, replace(request, chain=chain)) == "DENY"
