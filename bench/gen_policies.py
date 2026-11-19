# bench/gen_policies.py
"""Synthetic OpenAPL policy generator for the latency grid.

Usage: python bench/gen_policies.py OUT_DIR --principals 100 --entitlements 1000 --seed 1

Writes one policy file per namespace plus base.apl.yaml (humans, delegation) and
requests.jsonl, in the conformance request shape (one JSON object per line, plus an
"intent" label that the SDK ignores).

Shape. `principals` is the number of agent principals; humans are request-side only
(claims.groups) and are not counted. `entitlements` is the TOTAL entitlement count,
`denies` of which are deny rules, so grants = entitlements - denies.
- Agents are split over K namespaces (K = min(20, max(2, principals // 5))). Within a
  namespace, agents sit at delegation level (position % 3): level-0 agents `acts_for`
  two namespace groups, and every level-1/2 agent is reachable by `may_delegate` from
  the previous level (1-2 parents), so allowed chains have depth 1-3 (a human origin
  plus 1-3 agents).
- A "capability" is a unique (namespace, verb, resource type). Each gets one group
  entitlement and three agent entitlements, over a glob resource `ns/type/*`. About 30%
  of all entitlements carry a CEL `when`; half of the agent ones also carry
  `otherwise: require_approval(role:mgr)`. About `denies` entitlements deny on a
  resource glob (`blocked-*`) or `account_status == 'closed'`.
- Requests are drawn by intent so that every timed request exercises a real path:
  allow, require-approval, blocked-resource deny, caller-without-grant deny,
  missing-delegation-edge deny, and wrong-group deny.
"""
import argparse
import itertools
import json
import math
import random
from dataclasses import dataclass, field
from pathlib import Path

import yaml

VERBS = ["read", "write", "refund", "approve", "export", "delete"]
GROUPS = [f"g{i}" for i in range(6)]
NOW = 1_000_000
INTENTS = [  # (intent, weight)
    ("allow", 45), ("approval", 15), ("deny-blocked", 10),
    ("deny-no-grant", 10), ("deny-no-edge", 10), ("deny-wrong-group", 10),
]


@dataclass
class GenInfo:
    out_dir: str
    principals: int
    entitlements: int
    denies: int
    seed: int
    namespaces: int
    capabilities: int
    when_entitlements: int
    requests: int
    intents: dict = field(default_factory=dict)


def _write_yaml(path: Path, doc: dict) -> None:
    path.write_text(yaml.safe_dump(doc, sort_keys=False, width=200), encoding="utf-8")


def generate(out_dir: str, *, principals: int, entitlements: int, denies: int, seed: int,
             n_requests: int = 2000) -> GenInfo:
    if denies >= entitlements:
        raise ValueError("denies must be < entitlements")
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.apl.yaml"):
        old.unlink()

    K = min(20, max(2, principals // 5))
    ns_groups = {k: [GROUPS[k % 6], GROUPS[(k + 1) % 6]] for k in range(K)}
    agents = [f"agent-{i}" for i in range(principals)]
    ns_agents: dict[int, list[str]] = {k: [] for k in range(K)}
    for i, a in enumerate(agents):
        ns_agents[i % K].append(a)
    level = {a: (i // K) % 3 for i, a in enumerate(agents)}
    ns_of = {a: i % K for i, a in enumerate(agents)}
    parents: dict[str, list[str]] = {a: [] for a in agents}
    for k in range(K):
        members = ns_agents[k]
        for pos, a in enumerate(members):
            if level[a] == 0:
                continue
            cands = [b for b in members[:pos] if level[b] == level[a] - 1]
            ps = [rng.choice(cands)]
            if len(cands) > 1 and rng.random() < 0.5:
                extra = rng.choice(cands)
                if extra not in ps:
                    ps.append(extra)
            parents[a] = ps
    children: dict[str, list[str]] = {a: [] for a in agents}
    for a, ps in parents.items():
        for p in ps:
            children[p].append(a)

    # Capabilities: unique (ns, verb, rtype) triples.
    n_grants = entitlements - denies
    n_caps = max(1, n_grants // 4)
    T = max(2, math.ceil(n_caps / (K * len(VERBS))))
    combos = list(itertools.product(range(K), VERBS, range(T)))
    rng.shuffle(combos)
    caps = combos[:n_caps]

    ents: dict[int, list[dict]] = {k: [] for k in range(K)}
    deny_ents: dict[int, list[dict]] = {k: [] for k in range(K)}
    cap_info = []  # dicts: ns, verb, rtype, group, agent ents [(agent, limit|None, otherwise)]
    when_count = 0
    made = 0

    def agent_ent(eid, agent, ns, verb, rt):
        nonlocal when_count
        e = {"id": eid, "grant_to": [agent], "action": f"ns{ns}.{verb}",
             "resource": f"ns{ns}/t{rt}/*"}
        limit, otherwise = None, False
        if rng.random() < 0.35:
            limit = rng.randint(100, 5000)
            e["when"] = [f"request.amount <= {limit}"]
            when_count += 1
            if rng.random() < 0.5:
                e["otherwise"] = "require_approval(role:mgr)"
                otherwise = True
        return e, (agent, limit, otherwise)

    for n, (ns, verb, rt) in enumerate(caps):
        g = rng.choice(ns_groups[ns])
        ge = {"id": f"cap{n}-grp", "grant_to": [f"group:{g}"], "action": f"ns{ns}.{verb}",
              "resource": f"ns{ns}/t{rt}/*"}
        if rng.random() < 0.2:
            ge["when"] = [f"'{g}' in chain.origin.groups"]
            when_count += 1
        ents[ns].append(ge)
        made += 1
        chosen = rng.sample(ns_agents[ns], min(3, len(ns_agents[ns])))
        info = {"ns": ns, "verb": verb, "rt": rt, "group": g, "agents": []}
        for j, a in enumerate(chosen):
            e, rec = agent_ent(f"cap{n}-ag{j}", a, ns, verb, rt)
            ents[ns].append(e)
            info["agents"].append(rec)
            made += 1
        cap_info.append(info)
    extra_i = 0
    while made < n_grants:  # remainder: extra agent grants on random capabilities
        info = rng.choice(cap_info)
        a = rng.choice(ns_agents[info["ns"]])
        e, rec = agent_ent(f"extra{extra_i}", a, info["ns"], info["verb"], info["rt"])
        ents[info["ns"]].append(e)
        info["agents"].append(rec)
        extra_i += 1
        made += 1

    blocked = []  # (cap info, kind)
    for d in range(denies):
        info = cap_info[d % len(cap_info)] if d < len(cap_info) else rng.choice(cap_info)
        ns, verb, rt = info["ns"], info["verb"], info["rt"]
        e = {"id": f"deny{d}", "grant_to": ["*"], "action": f"ns{ns}.{verb}"}
        if d % 2 == 0:
            e["resource"] = f"ns{ns}/t{rt}/blocked-*"
            kind = "glob"
        else:
            e["resource"] = f"ns{ns}/t{rt}/*"
            e["when"] = ["request.account_status == 'closed'"]
            when_count += 1
            kind = "closed"
        deny_ents[ns].append(e)
        blocked.append((info, kind))

    # Policy files.
    _write_yaml(out / "base.apl.yaml", {
        "openapl": "0.1", "policy": "base", "version": "1.0.0",
        "humans": {"source": "idp", "match": {"groups_claim": "groups", "roles_claim": "roles"}},
        "delegation": {"max_depth": 3, "require_human_origin": True},
    })
    for k in range(K):
        pr = {}
        for a in ns_agents[k]:
            p = {"kind": "agent", "identity": {"oauth_client_id": a}, "owner": "owner@acme.com"}
            if level[a] == 0:
                p["acts_for"] = [{"who": f"group:{g}", "actions": [f"ns{k}.*"]}
                                 for g in ns_groups[k]]
            if children[a]:
                p["may_delegate"] = [{"to": c, "actions": [f"ns{k}.*"]} for c in children[a]]
            pr[a] = p
        doc = {"openapl": "0.1", "policy": f"ns{k}", "version": "1.0.0", "principals": pr}
        if ents[k]:
            doc["entitlements"] = ents[k]
        if deny_ents[k]:
            doc["deny"] = deny_ents[k]
        _write_yaml(out / f"ns{k:02d}.apl.yaml", doc)

    # Requests.
    humans = [f"user:h{j}@acme.com" for j in range(max(5, principals // 2))]

    def human(group, extra=True):
        other = rng.choice(GROUPS)
        gs = [group] if (other == group or not extra) else [group, other]
        return {"id": rng.choice(humans), "kind": "human", "claims": {"groups": gs}}

    def path_to(a):
        p = [a]
        while parents[p[0]]:
            p.insert(0, rng.choice(parents[p[0]]))
        return p

    def agent_links(ids):
        return [{"id": i, "kind": "agent"} for i in ids]

    def req(chain, info, rid, amount, status="open"):
        return {"chain": chain, "action": f"ns{info['ns']}.{info['verb']}",
                "resource": f"ns{info['ns']}/t{info['rt']}/{rid}",
                "attributes": {"amount": amount, "account_status": status},
                "now": NOW}

    weights = [w for _, w in INTENTS]
    appr_caps = [(i, rec) for i in cap_info for rec in i["agents"] if rec[2]]
    reqs, counts = [], {n: 0 for n, _ in INTENTS}
    for r in range(n_requests):
        intent = rng.choices([n for n, _ in INTENTS], weights)[0]
        if intent == "approval" and not appr_caps:
            intent = "allow"
        rid = f"r{r}"
        if intent == "allow":
            info = rng.choice(cap_info)
            a, limit, _ = rng.choice(info["agents"])
            q = req([human(info["group"])] + agent_links(path_to(a)), info, rid,
                    rng.randint(1, 100))
        elif intent == "approval":
            info, (a, limit, _) = rng.choice(appr_caps)
            q = req([human(info["group"])] + agent_links(path_to(a)), info, rid, limit + 1)
        elif intent == "deny-blocked":
            info, kind = rng.choice(blocked)
            a, _, _ = rng.choice(info["agents"])
            chain = [human(info["group"])] + agent_links(path_to(a))
            if kind == "glob":
                q = req(chain, info, f"blocked-{r}", rng.randint(1, 100))
            else:
                q = req(chain, info, rid, rng.randint(1, 100), "closed")
        elif intent == "deny-no-grant":
            info = rng.choice(cap_info)
            granted = {x[0] for x in info["agents"]}
            others = [a for a in ns_agents[info["ns"]] if a not in granted]
            a = rng.choice(others or ns_agents[info["ns"]])
            q = req([human(info["group"])] + agent_links(path_to(a)), info, rid, 10)
        elif intent == "deny-no-edge":
            info = rng.choice(cap_info)
            deep = [a for a in ns_agents[info["ns"]] if level[a] > 0]
            a = rng.choice(deep or ns_agents[info["ns"]])
            q = req([human(info["group"]), {"id": a, "kind": "agent"}], info, rid, 10)
        else:  # deny-wrong-group
            # TODO: misnamed. The origin human's group has no acts_for edge to the first agent
            # (the denial is "no acts_for edge for this group"). Rename to deny-no-acts-for-edge
            # at the next regeneration of latency.json; not renamed now so the recorded labels
            # stay stable (see bench/README.md).
            info = rng.choice(cap_info)
            bad = [g for g in GROUPS if g not in ns_groups[info["ns"]]]
            a = rng.choice(info["agents"])[0]
            q = req([human(rng.choice(bad), extra=False)] + agent_links(path_to(a)), info, rid, 10)
        q["intent"] = intent
        counts[intent] += 1
        reqs.append(q)
    (out / "requests.jsonl").write_text(
        "".join(json.dumps(q, sort_keys=True) + "\n" for q in reqs), encoding="utf-8")
    return GenInfo(out_dir=str(out), principals=principals, entitlements=entitlements,
                   denies=denies, seed=seed, namespaces=K, capabilities=len(cap_info),
                   when_entitlements=when_count, requests=n_requests, intents=counts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--principals", type=int, required=True)
    ap.add_argument("--entitlements", type=int, required=True)
    ap.add_argument("--denies", type=int)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    d = a.denies if a.denies is not None else round(0.05 * a.entitlements)
    print(generate(a.out_dir, principals=a.principals, entitlements=a.entitlements,
                   denies=d, seed=a.seed))


if __name__ == "__main__":
    main()
