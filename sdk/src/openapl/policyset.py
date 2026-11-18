# sdk/src/openapl/policyset.py
"""Load a directory of *.apl.yaml files into a PolicySet."""
import json
from pathlib import Path

import yaml

from openapl import schema
from openapl.model import Edge, Entitlement, PolicyLoadError, PolicySet, Principal

_FRAMEWORKS = {"NIST-800-53", "SOC2"}


def _edges(items, key: str) -> tuple[Edge, ...]:
    return tuple(
        Edge(actions=tuple(i["actions"]), **{key: i[key]}) for i in (items or [])
    )


def load_policy_dir(path: str, directory_snapshot: str | None = None) -> PolicySet:
    principals: dict[str, Principal] = {}
    ent_files: dict[str, str] = {}
    entitlements: list[Entitlement] = []
    frameworks: dict[str, tuple[str, ...]] = {}
    delegation: dict = {}
    humans: dict = {}
    seen_block: dict[str, str] = {}

    for f in sorted(Path(path).glob("*.apl.yaml")):
        fname = f.name
        try:
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as e:
            raise PolicyLoadError(f"{fname}: invalid YAML: {e}") from e
        for doc in docs:
            if not isinstance(doc, dict):
                raise PolicyLoadError(f"{fname}: document is not a mapping")
            try:
                schema.validate(doc)
            except ValueError as e:
                raise PolicyLoadError(f"{fname}: {e}") from e
            source = f"{doc['policy']}@{doc['version']}"
            comp = tuple(doc.get("compliance") or ())
            for fw in comp:
                if fw not in _FRAMEWORKS:
                    raise PolicyLoadError(f"{fname}: unknown compliance framework {fw!r}")
            frameworks[source] = comp

            for block, target in (("delegation", delegation), ("humans", humans)):
                if block in doc:
                    if block in seen_block:
                        raise PolicyLoadError(
                            f"{block} block defined in both {seen_block[block]} and {fname}"
                        )
                    seen_block[block] = fname
                    target.update(doc[block] or {})

            for pid, p in (doc.get("principals") or {}).items():
                if pid in principals:
                    raise PolicyLoadError(
                        f"duplicate principal {pid!r} in {principals[pid].source_file} and {fname}"
                    )
                if not p.get("owner"):
                    raise PolicyLoadError(f"{fname}: principal {pid!r} has no owner")
                principals[pid] = Principal(
                    id=pid,
                    kind=p["kind"],
                    identity=dict(p.get("identity") or {}),
                    owner=p["owner"],
                    acts_for=_edges(p.get("acts_for"), "who"),
                    may_delegate=_edges(p.get("may_delegate"), "to"),
                    source=source,
                    source_file=fname,
                )

            for key, is_deny in (("entitlements", False), ("deny", True)):
                for e in doc.get(key) or []:
                    eid = e["id"]
                    if eid in ent_files:
                        raise PolicyLoadError(
                            f"duplicate entitlement id {eid!r} in {ent_files[eid]} and {fname}"
                        )
                    ent_files[eid] = fname
                    expires = e.get("expires", "never")
                    if expires == "task" and not e.get("purpose"):
                        raise PolicyLoadError(
                            f"{fname}: entitlement {eid!r} has expires: task but no purpose"
                        )
                    entitlements.append(
                        Entitlement(
                            id=eid,
                            grant_to=tuple(e["grant_to"]),
                            action=e["action"],
                            resource=e["resource"],
                            when=tuple(e.get("when") or ()),
                            purpose=e.get("purpose"),
                            expires=expires,
                            otherwise=e.get("otherwise"),
                            deny=is_deny,
                            source=source,
                            source_file=fname,
                        )
                    )

    for p in principals.values():
        for edge in p.may_delegate:
            if edge.to not in principals:
                raise PolicyLoadError(
                    f"{p.source_file}: principal {p.id!r} may_delegate to unknown principal {edge.to!r}"
                )

    active = None
    if directory_snapshot is not None:
        try:
            data = json.loads(Path(directory_snapshot).read_text(encoding="utf-8"))
            active = frozenset(data["active"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise PolicyLoadError(f"directory snapshot {directory_snapshot}: {e}") from e

    match = humans.get("match") or {}
    return PolicySet(
        principals=principals,
        entitlements=tuple(entitlements),
        max_depth=delegation.get("max_depth", 3),
        require_human_origin=delegation.get("require_human_origin", True),
        groups_claim=match.get("groups_claim", "groups"),
        roles_claim=match.get("roles_claim", "roles"),
        frameworks=frameworks,
        active_humans=active,
    )
