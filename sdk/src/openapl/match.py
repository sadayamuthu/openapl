# sdk/src/openapl/match.py
"""Action, resource and selector matching."""
import re
from fnmatch import fnmatchcase

from openapl.model import Link, PolicySet

_PLACEHOLDER = re.compile(r"\$\{request\.([^}]+)\}")
_GLOB_CHARS = re.compile(r"[*?\[]")


def match_action(pattern: str, action: str) -> bool:
    return pattern == action or fnmatchcase(action, pattern)


def actions_overlap(p: str, q: str) -> bool:
    """True when two glob patterns could match a common action (conservative)."""
    if not (_GLOB_CHARS.search(p) or _GLOB_CHARS.search(q)):
        return p == q

    def parts(x: str) -> tuple[str, str]:
        first = _GLOB_CHARS.search(x)
        if first is None:
            return x, x
        last = max(i for i, c in enumerate(x) if c in "*?[")
        return x[:first.start()], x[last + 1:]

    (p_pre, p_suf), (q_pre, q_suf) = parts(p), parts(q)
    if not (p_pre.startswith(q_pre) or q_pre.startswith(p_pre)):
        return False
    if "[" in p or "[" in q:
        return True  # a class body makes the literal suffix unreliable; prefix check only
    return p_suf.endswith(q_suf) or q_suf.endswith(p_suf)


def _escape(value: str) -> str:
    # Bracket-escape so an attribute value is matched literally, never as a glob.
    return _GLOB_CHARS.sub(lambda m: "[" + m.group(0) + "]", value)


def match_resource(pattern: str, resource: str, attributes: dict) -> bool:
    missing = False

    def sub(m: re.Match) -> str:
        nonlocal missing
        key = m.group(1)
        if key not in attributes:
            missing = True
            return ""
        return _escape(str(attributes[key]))

    expanded = _PLACEHOLDER.sub(sub, pattern)
    if missing:
        return False
    return fnmatchcase(resource, expanded)


def match_deny_resource(pattern: str, resource: str) -> bool:
    # R7: a deny matches in un-interpolated wildcard form; every ${...} is `*`,
    # so request attributes can never narrow or skip a deny.
    return fnmatchcase(resource, _PLACEHOLDER.sub("*", pattern))


def selector_matches(selector: str, link: Link, ps: PolicySet) -> bool:
    if selector == "*":
        return True
    if selector.startswith("user:"):
        return link.kind == "human" and link.principal_id == selector
    if selector.startswith(("group:", "role:")):
        if link.kind != "human":
            return False
        prefix, _, name = selector.partition(":")
        claim = ps.groups_claim if prefix == "group" else ps.roles_claim
        values = link.claims.get(claim)
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, (list, tuple)):
            return False
        return name in values
    return selector == link.principal_id
