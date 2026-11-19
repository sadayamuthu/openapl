# sidecar/src/openapl_sidecar/bindings.py
import math
import re
from dataclasses import dataclass
from typing import Any

import yaml


class BindingError(ValueError):
    pass


@dataclass(frozen=True)
class ToolBinding:
    tool: str
    target: str | None
    action: str
    resource: str
    attributes: dict[str, str]


@dataclass(frozen=True)
class Bindings:
    tools: tuple[ToolBinding, ...]
    targets: tuple[str, ...]
    prefix_mode: str
    default_action: str
    default_resource: str
    passthrough_methods: frozenset[str]


_DEFAULT_ACTION = "mcp.tools.call:${target}/${tool}"
_DEFAULT_RESOURCE = "tool:${target}/${tool}"
_DEFAULT_PASSTHROUGH = frozenset({"initialize", "ping", "tools/list"})

DEFAULT_BINDINGS = Bindings(
    tools=(),
    targets=(),
    prefix_mode="conditional",
    default_action=_DEFAULT_ACTION,
    default_resource=_DEFAULT_RESOURCE,
    passthrough_methods=_DEFAULT_PASSTHROUGH,
)

_PLACEHOLDER = re.compile(r"\$\{(args(?:\.[A-Za-z0-9_-]+)+|target|tool)\}")
_TOP_KEYS = {"version", "targets", "prefix_mode", "passthrough_methods", "default_action",
             "default_resource", "tools"}
_TOOL_KEYS = {"tool", "target", "action", "resource", "attributes"}
_PREFIX_MODES = ("conditional", "always", "never")


def _check_template(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise BindingError(f"{where} must be a string template, got {value!r}")
    if "${" in _PLACEHOLDER.sub("", value):
        raise BindingError(f"invalid placeholder in {where}: {value!r}")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise BindingError(f"{where} must be a list of strings")
    return value


def load_bindings(path: str | None) -> Bindings:
    if path is None:
        return DEFAULT_BINDINGS
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise BindingError(f"cannot read bindings file {path}: {e}") from e
    if not isinstance(doc, dict):
        raise BindingError("bindings file must be a mapping")
    v = doc.get("version")
    if type(v) is not int or v != 1:
        raise BindingError("bindings file requires version: 1")
    unknown = set(doc) - _TOP_KEYS
    if unknown:
        raise BindingError(f"unknown top-level key(s): {', '.join(sorted(map(str, unknown)))}")

    targets = _str_list(doc.get("targets", []), "targets")
    for t in targets:
        if "_" in t:
            raise BindingError(f"target name {t!r} must not contain '_'")
    prefix_mode = doc.get("prefix_mode", "conditional")
    if prefix_mode not in _PREFIX_MODES:
        raise BindingError(f"prefix_mode must be one of {', '.join(_PREFIX_MODES)}")
    passthrough = (frozenset(_str_list(doc["passthrough_methods"], "passthrough_methods"))
                   if "passthrough_methods" in doc else _DEFAULT_PASSTHROUGH)
    default_action = _check_template(doc.get("default_action", _DEFAULT_ACTION), "default_action")
    default_resource = _check_template(doc.get("default_resource", _DEFAULT_RESOURCE), "default_resource")

    entries = doc.get("tools", [])
    if not isinstance(entries, list):
        raise BindingError("tools must be a list")
    tools: list[ToolBinding] = []
    seen: set[tuple[str | None, str]] = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise BindingError(f"tools[{i}] must be a mapping")
        bad = set(e) - _TOOL_KEYS
        if bad:
            raise BindingError(f"tools[{i}]: key not allowed: {', '.join(sorted(map(str, bad)))}")
        for req in ("tool", "action", "resource"):
            if req not in e:
                raise BindingError(f"tools[{i}]: missing '{req}'")
        tool, target = e["tool"], e.get("target")
        if not isinstance(tool, str) or (target is not None and not isinstance(target, str)):
            raise BindingError(f"tools[{i}]: tool and target must be strings")
        if target is not None and "_" in target:
            raise BindingError(f"tools[{i}]: target name {target!r} must not contain '_'")
        if (target, tool) in seen:
            raise BindingError(f"duplicate binding for target={target!r} tool={tool!r}")
        seen.add((target, tool))
        attrs = e.get("attributes", {})
        if not isinstance(attrs, dict):
            raise BindingError(f"tools[{i}]: attributes must be a mapping")
        tools.append(ToolBinding(
            tool=tool,
            target=target,
            action=_check_template(e["action"], f"tools[{i}].action"),
            resource=_check_template(e["resource"], f"tools[{i}].resource"),
            attributes={str(k): _check_template(v, f"tools[{i}].attributes.{k}") for k, v in attrs.items()},
        ))
    return Bindings(tuple(tools), tuple(targets), prefix_mode, default_action, default_resource, passthrough)


def resolve_tool(b: Bindings, wire_name: str) -> tuple[str | None, str]:
    split = b.prefix_mode == "always" or (b.prefix_mode == "conditional" and len(b.targets) > 1)
    if split:
        prefix, sep, tool = wire_name.partition("_")
        if not sep or not tool or prefix not in b.targets:
            raise BindingError(f"cannot resolve target for tool {wire_name!r}")
        return prefix, tool
    if b.prefix_mode == "never":
        return (b.targets[0] if len(b.targets) == 1 else None), wire_name
    return (b.targets[0] if b.targets else None), wire_name


def _lookup(b: Bindings, target: str | None, tool: str) -> ToolBinding | None:
    generic = None
    for t in b.tools:
        if t.tool != tool:
            continue
        if t.target is None:
            generic = t
        elif t.target == target:
            return t
    return generic


def _value(ref: str, target: str | None, tool: str, args: dict, token: str) -> Any:
    if ref == "tool":
        return tool
    if ref == "target":
        if target is None:
            raise BindingError(f"unbound placeholder {token}")
        return target
    cur: Any = args
    for part in ref.split(".")[1:]:
        if not isinstance(cur, dict) or part not in cur:
            raise BindingError(f"unbound placeholder {token}")
        cur = cur[part]
    if cur is None or not isinstance(cur, (str, int, float, bool)):
        raise BindingError(f"unbound placeholder {token}")
    if isinstance(cur, float) and not math.isfinite(cur):
        raise BindingError(f"unbound placeholder {token}: non-finite number")
    return cur


def _render(template: str, target: str | None, tool: str, args: dict, keep_type: bool) -> Any:
    whole = _PLACEHOLDER.fullmatch(template)
    if whole and keep_type:
        return _value(whole.group(1), target, tool, args, template)

    def sub(m: re.Match) -> str:
        v = _value(m.group(1), target, tool, args, m.group(0))
        if isinstance(v, bool):
            return "true" if v else "false"
        return str(v)

    return _PLACEHOLDER.sub(sub, template)


def map_call(b: Bindings, wire_name: str, arguments: dict) -> tuple[str, str, dict]:
    target, tool = resolve_tool(b, wire_name)
    entry = _lookup(b, target, tool)
    if entry is None:
        action_t, resource_t, attr_ts = b.default_action, b.default_resource, {}
    else:
        action_t, resource_t, attr_ts = entry.action, entry.resource, entry.attributes
    action = _render(action_t, target, tool, arguments, False)
    resource = _render(resource_t, target, tool, arguments, False)
    attributes = {k: _render(t, target, tool, arguments, True) for k, t in attr_ts.items()}
    return action, resource, attributes
