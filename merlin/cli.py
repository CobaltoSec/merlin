"""Merlin CLI entrypoint. Implementation pending — see DESIGN.md."""

import typer

app = typer.Typer(help="Merlin — LLM Attack Surface Framework")


@app.command()
def scan(target: str) -> None:
    """Scan a target LLM endpoint for OWASP LLM Top 10 issues (not yet implemented)."""
    typer.echo(f"merlin scan --target {target} — not yet implemented (v0.1.0-pre)")
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
