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
