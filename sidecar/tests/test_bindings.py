# sidecar/tests/test_bindings.py
import pytest

from openapl_sidecar.bindings import (DEFAULT_BINDINGS, BindingError, load_bindings, map_call,
                                      resolve_tool)


def make(tmp_path, text):
    p = tmp_path / "b.yaml"
    p.write_text(text)
    return load_bindings(str(p))


def test_refund_binding_keeps_number_type(bindings_file):
    b = load_bindings(bindings_file)
    assert map_call(b, "refund_order", {"order_id": "123", "amount": 150, "account_status": "open"}) == (
        "payments.refund", "order/123", {"order_id": "123", "amount": 150, "account_status": "open"})


def test_default_binding_without_target_is_unbound():
    with pytest.raises(BindingError, match=r"\$\{target\}"):
        map_call(DEFAULT_BINDINGS, "lookup", {})


def test_default_binding_single_target(tmp_path):
    b = make(tmp_path, "version: 1\ntargets: [crm]\n")
    assert map_call(b, "lookup", {}) == ("mcp.tools.call:crm/lookup", "tool:crm/lookup", {})


def test_default_bindings_values():
    assert DEFAULT_BINDINGS.prefix_mode == "conditional"
    assert DEFAULT_BINDINGS.targets == ()
    assert DEFAULT_BINDINGS.passthrough_methods == frozenset({"initialize", "ping", "tools/list"})


def test_load_none_gives_default():
    assert load_bindings(None) is DEFAULT_BINDINGS


def test_prefix_split_multi_target(tmp_path):
    b = make(tmp_path, "version: 1\ntargets: [payments, crm]\n")
    assert resolve_tool(b, "payments_refund_order") == ("payments", "refund_order")
    with pytest.raises(BindingError, match="cannot resolve target for tool 'billing_x'"):
        resolve_tool(b, "billing_x")
    with pytest.raises(BindingError):
        resolve_tool(b, "noprefix")


def test_conditional_single_target_no_split(tmp_path):
    b = make(tmp_path, "version: 1\ntargets: [refund]\n")
    assert resolve_tool(b, "refund_order") == ("refund", "refund_order")


def test_conditional_no_targets(tmp_path):
    assert resolve_tool(make(tmp_path, "version: 1\n"), "a_b") == (None, "a_b")


def test_always_mode(tmp_path):
    b = make(tmp_path, "version: 1\ntargets: [crm]\nprefix_mode: always\n")
    assert resolve_tool(b, "crm_lookup") == ("crm", "lookup")
    with pytest.raises(BindingError):
        resolve_tool(b, "lookup")


def test_never_mode(tmp_path):
    one = make(tmp_path, "version: 1\ntargets: [crm]\nprefix_mode: never\n")
    assert resolve_tool(one, "crm_lookup") == ("crm", "crm_lookup")
    two = make(tmp_path, "version: 1\ntargets: [crm, hr]\nprefix_mode: never\n")
    assert resolve_tool(two, "crm_lookup") == (None, "crm_lookup")


def test_bad_prefix_mode(tmp_path):
    with pytest.raises(BindingError):
        make(tmp_path, "version: 1\nprefix_mode: sometimes\n")


def test_target_specific_beats_generic(tmp_path):
    b = make(tmp_path, """
version: 1
targets: [a, b]
tools:
  - {tool: t, action: generic, resource: g}
  - {tool: t, target: a, action: specific, resource: s}
""")
    assert map_call(b, "a_t", {})[:2] == ("specific", "s")
    assert map_call(b, "b_t", {})[:2] == ("generic", "g")


@pytest.mark.parametrize("key", ["purpose", "task", "approvals"])
def test_forbidden_binding_key(tmp_path, key):
    with pytest.raises(BindingError, match=key):
        make(tmp_path, f"version: 1\ntools:\n  - {{tool: t, action: a, resource: r, {key}: x}}\n")


def test_unknown_top_level_key(tmp_path):
    with pytest.raises(BindingError, match="bogus"):
        make(tmp_path, "version: 1\nbogus: 1\n")


@pytest.mark.parametrize("ph", ["${request.x}", "${args.}", "${ args.x }", "${args}", "${"])
def test_bad_placeholder(tmp_path, ph):
    with pytest.raises(BindingError):
        make(tmp_path, f'version: 1\ntools:\n  - {{tool: t, action: "{ph}", resource: r}}\n')


def test_bad_placeholder_in_attributes_and_defaults(tmp_path):
    with pytest.raises(BindingError):
        make(tmp_path, 'version: 1\ntools:\n  - {tool: t, action: a, resource: r, attributes: {x: "${bad}"}}\n')
    with pytest.raises(BindingError):
        make(tmp_path, 'version: 1\ndefault_action: "${bad}"\n')


def test_target_with_underscore_rejected(tmp_path):
    with pytest.raises(BindingError, match="_"):
        make(tmp_path, "version: 1\ntargets: [my_target]\n")


def test_duplicate_binding_rejected(tmp_path):
    with pytest.raises(BindingError, match="duplicate"):
        make(tmp_path, """
version: 1
tools:
  - {tool: t, target: a, action: x, resource: r}
  - {tool: t, target: a, action: y, resource: r}
""")


def test_version_required(tmp_path):
    with pytest.raises(BindingError, match="version"):
        make(tmp_path, "targets: [a]\n")


@pytest.mark.parametrize("args", [{}, {"order_id": None}, {"order_id": {"x": 1}}, {"order_id": [1]}])
def test_unbound_placeholder(tmp_path, args):
    b = make(tmp_path, 'version: 1\ntools:\n  - {tool: t, action: a, resource: "o/${args.order_id}"}\n')
    with pytest.raises(BindingError, match=r"unbound placeholder \$\{args\.order_id\}"):
        map_call(b, "t", args)


def test_nested_args_and_types(tmp_path):
    b = make(tmp_path, """
version: 1
tools:
  - tool: t
    action: a
    resource: r
    attributes: {n: "${args.o.n}", f: "${args.o.f}", ok: "${args.ok}", s: "${args.o.s}"}
""")
    _, _, attrs = map_call(b, "t", {"o": {"n": 1, "f": 1.5, "s": "x"}, "ok": True})
    assert attrs == {"n": 1, "f": 1.5, "ok": True, "s": "x"}
    assert type(attrs["ok"]) is bool


def test_mixed_template_is_string(tmp_path):
    b = make(tmp_path, 'version: 1\ntools:\n  - {tool: t, action: a, resource: r, attributes: {id: "o-${args.n}"}}\n')
    assert map_call(b, "t", {"n": 5})[2] == {"id": "o-5"}


def test_action_resource_always_string(tmp_path):
    b = make(tmp_path, 'version: 1\ntools:\n  - {tool: t, action: "${args.n}", resource: "${args.n}"}\n')
    assert map_call(b, "t", {"n": 5})[:2] == ("5", "5")


def test_attribute_non_string_template_rejected(tmp_path):
    with pytest.raises(BindingError):
        make(tmp_path, "version: 1\ntools:\n  - {tool: t, action: a, resource: r, attributes: {x: 1}}\n")


def test_missing_file(tmp_path):
    with pytest.raises(BindingError):
        load_bindings(str(tmp_path / "nope.yaml"))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("tmpl", ["${args.n}", "o-${args.n}"])
def test_non_finite_number_rejected(tmp_path, bad, tmpl):
    b = make(tmp_path, f'version: 1\ntools:\n  - {{tool: t, action: a, resource: r, attributes: {{x: "{tmpl}"}}}}\n')
    with pytest.raises(BindingError, match="non-finite"):
        map_call(b, "t", {"n": bad})


def test_empty_tool_name_rejected(tmp_path):
    b = make(tmp_path, "version: 1\ntargets: [payments, crm]\n")
    with pytest.raises(BindingError):
        resolve_tool(b, "payments_")


@pytest.mark.parametrize("v", ["true", "1.0"])
def test_version_must_be_int_one(tmp_path, v):
    with pytest.raises(BindingError, match="version"):
        make(tmp_path, f"version: {v}\n")
