# sdk/src/openapl/cli.py
"""The openapl command line."""
from pathlib import Path

import click

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
