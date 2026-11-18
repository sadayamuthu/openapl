# sdk/src/openapl/cli.py
"""The openapl command line."""
import json
import re
import time
from pathlib import Path

import click

from openapl.approvals import approval_from_claim
from openapl.authorizer import Authorizer
from openapl.chain import ChainError, chain_from_list
from openapl.decision_log import DecisionLog
from openapl.model import Request
from openapl.policyset import load_policy_dir


@click.group()
def main() -> None:
    """OpenAPL: an open access-policy language for humans and AI agents."""


@main.command()
@click.argument("policy_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--directory", "directory", type=click.Path(), default=None,
              help="JSON snapshot of active humans.")
def validate(policy_dir: str, directory: str | None) -> None:
    """Validate every *.apl.yaml file in POLICY_DIR."""
    try:
        ps = load_policy_dir(policy_dir, directory)
    except ValueError as e:  # PolicyLoadError is a ValueError
        click.echo(f"✗ {e}")
        raise SystemExit(1)
    files = len(list(Path(policy_dir).glob("*.apl.yaml")))
    denies = sum(1 for e in ps.entitlements if e.deny)
    grants = len(ps.entitlements) - denies
    click.echo(f"✓ {len(ps.principals)} principals, {grants} entitlements, {denies} denies from {files} files")


_INT_RE = re.compile(r"-?[0-9]+")
_FLOAT_RE = re.compile(r"-?[0-9]+\.[0-9]+")


def _parse_value(text: str):
    if _INT_RE.fullmatch(text):
        return int(text)
    if _FLOAT_RE.fullmatch(text):
        return float(text)
    return text


def _usage_error(msg: str) -> None:
    click.echo(f"✗ {msg}", err=True)
    raise SystemExit(1)


_EXIT = {"ALLOW": 0, "DENY": 3, "REQUIRE_APPROVAL": 4}
_COLOR = {"ALLOW": "green", "DENY": "red", "REQUIRE_APPROVAL": "yellow"}


@main.command()
@click.argument("policy_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--chain", "chain_text", required=True, help="Comma-separated principal ids, human first.")
@click.option("--action", required=True)
@click.option("--resource", required=True)
@click.option("--attr", "attrs", multiple=True, help="k=v request attribute (repeatable).")
@click.option("--purpose", default=None)
@click.option("--task-id", "task_id", default=None)
@click.option("--iat", "token_iat", type=int, default=None)
@click.option("--now", type=int, default=None, help="Unix time; defaults to the current time.")
@click.option("--origin-claims", "origin_claims", default=None, help="JSON object of origin claims.")
@click.option("--approval", "approvals", multiple=True, help="JSON approval object (repeatable).")
@click.option("--directory", "directory", type=click.Path(), default=None,
              help="JSON snapshot of active humans.")
@click.option("--log", "log_path", type=click.Path(), default=None, help="Append the decision to this file.")
@click.option("--json", "as_json", is_flag=True, help="Print the decision as JSON.")
def decide(policy_dir, chain_text, action, resource, attrs, purpose, task_id, token_iat,
           now, origin_claims, approvals, directory, log_path, as_json) -> None:
    """Decide one request against POLICY_DIR (dev mode)."""
    try:
        authorizer = Authorizer.from_dir(policy_dir, directory)
    except ValueError as e:
        _usage_error(str(e))
    attributes = {}
    for item in attrs:
        if "=" not in item:
            _usage_error(f"--attr expects k=v, got {item!r}")
        k, v = item.split("=", 1)
        attributes[k] = _parse_value(v)
    claims = None
    if origin_claims is not None:
        try:
            claims = json.loads(origin_claims)
        except ValueError as e:
            _usage_error(f"--origin-claims is not valid JSON: {e}")
        if not isinstance(claims, dict):
            _usage_error("--origin-claims must be a JSON object")
    parsed = []
    for raw in approvals:
        try:
            parsed.append(approval_from_claim(json.loads(raw)))
        except ValueError as e:
            _usage_error(f"bad --approval: {e}")
    try:
        chain = chain_from_list([c.strip() for c in chain_text.split(",")], authorizer.ps, claims)
    except ChainError as e:
        _usage_error(str(e))
    request = Request(
        chain=chain, action=action, resource=resource, attributes=attributes,
        purpose=purpose, task_id=task_id, token_iat=token_iat,
        now=int(time.time()) if now is None else now,
        approvals=tuple(parsed), dev_mode=True)
    decision = authorizer.decide(request)
    if as_json:
        click.echo(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
    else:
        click.echo(click.style(f"DECISION: {decision.decision}", fg=_COLOR[decision.decision], bold=True))
        for reason in decision.reasons:
            click.echo(f"  → {reason}")
    if log_path is not None:
        try:
            DecisionLog(log_path).append(decision)
        except OSError as e:
            click.echo(f"✗ cannot write decision log: {e}", err=True)
            raise SystemExit(1)
    raise SystemExit(_EXIT[decision.decision])


def _load_or_exit(policy_dir: str):
    try:
        return load_policy_dir(policy_dir)
    except ValueError as e:
        click.echo(f"✗ {e}", err=True)
        raise SystemExit(1)


@main.command()
@click.argument("policy_dir", type=click.Path(exists=True, file_okay=False))
@click.argument("principal")
@click.option("--on-behalf-of", "on_behalf_of", default=None,
              help="user:/group:/role: selector; narrow reach to work done for such a human.")
@click.option("--json", "as_json", is_flag=True, help="Print the explanation as JSON.")
def explain(policy_dir: str, principal: str, on_behalf_of: str | None, as_json: bool) -> None:
    """Show what PRINCIPAL could cause if it were hijacked."""
    from openapl.explain import edge_dict, explain as explain_principal

    ps = _load_or_exit(policy_dir)
    try:
        ex = explain_principal(ps, principal, on_behalf_of)
    except KeyError:
        click.echo(f"✗ unknown principal {principal}", err=True)
        raise SystemExit(1)
    p = ex.principal
    if as_json:
        click.echo(json.dumps({
            "principal": p.id, "kind": p.kind, "owner": p.owner, "identity": p.identity,
            "acts_for": [edge_dict(e) for e in ex.acts_for],
            "entitlements": [e.id for e in ex.entitlements],
            "delegates_to": [edge_dict(e) for e in ex.delegates_to],
            "delegated_from": [{"principal": pid, **edge_dict(e)} for pid, e in ex.delegated_from],
            "reach": [{"action": r.action, "resource": r.resource, "via": list(r.via),
                       "entitlement_id": r.entitlement_id} for r in ex.reach],
        }, ensure_ascii=False, indent=2))
        return
    none = "  (none)"
    click.echo(f"PRINCIPAL\n  {p.id} ({p.kind})")
    click.echo(f"OWNER\n  {p.owner}")
    click.echo("ACTS FOR")
    click.echo("\n".join(f"  {e.who}: {', '.join(e.actions)}" for e in ex.acts_for) or none)
    click.echo("ENTITLEMENTS")
    click.echo("\n".join(f"  {e.id}: {e.action}  {e.resource}" for e in ex.entitlements) or none)
    click.echo("CAN DELEGATE")
    click.echo("\n".join(f"  {e.to}: {', '.join(e.actions)}" for e in ex.delegates_to) or none)
    click.echo("DELEGATED FROM")
    click.echo("\n".join(f"  {pid}: {', '.join(e.actions)}" for pid, e in ex.delegated_from) or none)
    suffix = f" (on behalf of {on_behalf_of})" if on_behalf_of else ""
    click.echo(f"REACH IF COMPROMISED{suffix}")
    click.echo("\n".join(f"  {r.action}  {r.resource}  via {' → '.join(r.via)}" for r in ex.reach) or none)


@main.command()
@click.argument("policy_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Print the inventory as JSON.")
def inventory(policy_dir: str, as_json: bool) -> None:
    """List every principal in POLICY_DIR."""
    from openapl.explain import inventory as build_inventory

    rows = build_inventory(_load_or_exit(policy_dir))
    if as_json:
        click.echo(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    click.echo(f"{'ID':<20} {'KIND':<8} {'OWNER':<20} ENTITLEMENTS")
    for r in rows:
        click.echo(f"{r['id']:<20} {r['kind']:<8} {r['owner']:<20} {', '.join(r['entitlements'])}")


@main.command()
@click.argument("log", type=click.Path(exists=True, dir_okay=False))
@click.option("--since", type=int, required=True, help="Window start, epoch seconds.")
@click.option("--until", type=int, required=True, help="Window end, epoch seconds.")
@click.option("--title", default="OpenAPL decision records", show_default=True)
@click.option("-o", "output", type=click.Path(), default=None, help="Write JSON here (default stdout).")
def evidence(log: str, since: int, until: int, title: str, output: str | None) -> None:
    """Export LOG decisions in a time window as OSCAL assessment-results."""
    import os
    from datetime import datetime, timezone

    from openapl.decision_log import read_log
    from openapl.evidence import assessment_results

    records, skipped = read_log(log, since, until)
    if skipped:
        click.echo(f"warning: skipped {skipped} malformed log line(s)", err=True)
    if not records:
        click.echo("✗ no decisions in the window", err=True)
        raise SystemExit(1)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = datetime.fromtimestamp(int(epoch) if epoch else time.time(), tz=timezone.utc)
    doc = assessment_results(records, title=title, since=since, until=until,
                             now=when.strftime("%Y-%m-%dT%H:%M:%SZ"))
    text = json.dumps(doc, ensure_ascii=False, indent=2)
    if output is None:
        click.echo(text)
    else:
        Path(output).write_text(text + "\n", encoding="utf-8")
