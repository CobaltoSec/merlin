"""Merlin CLI entrypoint."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from merlin import __version__
from merlin.core.fingerprint import run_fingerprint
from merlin.core.http_client import AsyncTargetClient, TargetCallError, TargetConfig
from merlin.core.session import EngagementSession
from merlin.generators.ollama import OllamaGenerator
from merlin.generators.static import StaticGenerator
from merlin.modules.excessive_agency import ExcessiveAgencyModule
from merlin.modules.prompt_injection import PromptInjectionModule
from merlin.modules.sensitive_info_disclosure import SensitiveInfoDisclosureModule
from merlin.modules.system_prompt_leak import SystemPromptLeakModule
from merlin.reporting.report import write_report

app = typer.Typer(
    help="Merlin — LLM Attack Surface Framework.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

GENERATORS = {
    "static": StaticGenerator,
    "ollama": OllamaGenerator,
}

MODULES = {
    "prompt-injection": PromptInjectionModule,
    "system-prompt-leak": SystemPromptLeakModule,
    "sensitive-info-disclosure": SensitiveInfoDisclosureModule,
    "excessive-agency": ExcessiveAgencyModule,
}


def _build_target_config(
    target: str,
    body_template: str | None,
    response_path: str,
    payload_placeholder: str,
    method: str,
    headers: str | None,
    timeout: float,
) -> TargetConfig:
    template_dict = {"message": "{payload}"}
    if body_template:
        try:
            template_dict = json.loads(body_template)
        except json.JSONDecodeError as e:
            console.print(f"[red]Invalid --body-template JSON: {e}[/red]")
            raise typer.Exit(code=2) from e

    header_dict: dict[str, str] = {}
    if headers:
        for chunk in headers.split(";"):
            if not chunk.strip():
                continue
            if ":" not in chunk:
                console.print(f"[red]Invalid header (no ':'): {chunk!r}[/red]")
                raise typer.Exit(code=2)
            k, _, v = chunk.partition(":")
            header_dict[k.strip()] = v.strip()

    return TargetConfig(
        url=target,
        method=method.upper(),
        headers=header_dict,
        body_template=template_dict,
        payload_placeholder=payload_placeholder,
        response_path=response_path,
        timeout_seconds=timeout,
    )


def _print_summary(session: EngagementSession) -> None:
    table = Table(title="Merlin scan summary", show_header=True, header_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in session.state.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    table.add_row("Critical", f"[bold red]{counts['critical']}[/bold red]")
    table.add_row("High", f"[red]{counts['high']}[/red]")
    table.add_row("Medium", f"[yellow]{counts['medium']}[/yellow]")
    table.add_row("Low", f"[dim]{counts['low']}[/dim]")
    table.add_row("[bold]Total[/bold]", f"[bold]{len(session.state.findings)}[/bold]")
    console.print(table)


async def _scan_async(
    target: str,
    module_name: str,
    gen_name: str,
    concurrency: int,
    rate_limit: float,
    output_dir: Path,
    canary: str,
    target_cfg: TargetConfig,
    ollama_host: str | None = None,
    ollama_model: str | None = None,
    variants_per_seed: int | None = None,
    max_payloads: int | None = None,
) -> tuple[EngagementSession, int]:
    if module_name not in MODULES:
        console.print(f"[red]Unknown module {module_name!r}. Choices: {list(MODULES)}[/red]")
        raise typer.Exit(code=2)
    if gen_name not in GENERATORS:
        console.print(f"[red]Unknown generator {gen_name!r}. Choices: {list(GENERATORS)}[/red]")
        raise typer.Exit(code=2)

    gen_kwargs: dict = {}
    if gen_name == "ollama":
        if ollama_host:
            gen_kwargs["host"] = ollama_host
        if ollama_model:
            gen_kwargs["model"] = ollama_model
        if variants_per_seed:
            gen_kwargs["variants_per_seed"] = variants_per_seed

    generator = GENERATORS[gen_name](**gen_kwargs)
    module = MODULES[module_name]()

    session = EngagementSession.create(target=target, output_root=output_dir, merlin_version=__version__)
    console.print(f"[cyan]→ Engagement[/cyan] {session.dir_path}")

    async with AsyncTargetClient(target_cfg) as client:
        console.print("[cyan]→ Fingerprinting target...[/cyan]")
        try:
            fp = await run_fingerprint(client)
        except TargetCallError as e:
            console.print(f"[red]Fingerprint failed: {e}[/red]")
            session.fail()
            return session, 2

        session.state.fingerprint = fp
        session.save()
        is_llm = fp.get("is_llm", False)
        confidence = fp.get("confidence", "unknown")
        latency = fp.get("latency_ms", 0.0)
        console.print(
            f"   target [b]{'recognized as LLM' if is_llm else 'NOT recognized as LLM'}[/b] "
            f"(confidence={confidence}, latency={latency:.0f}ms)"
        )

        gen_context = {"fingerprint": fp}
        if gen_name == "ollama":
            console.print(f"[cyan]→ Generating variants via Ollama[/cyan] ({generator.model} @ {generator.host})")
        payloads = generator.generate(module.category, context=gen_context)
        if max_payloads is not None and max_payloads > 0 and len(payloads) > max_payloads:
            console.print(
                f"[cyan]→ Trimming payloads {len(payloads)} → {max_payloads} (--max-payloads)[/cyan]"
            )
            payloads = payloads[:max_payloads]
        if not payloads:
            console.print("[yellow]⚠ generator returned 0 payloads — nothing to scan[/yellow]")
            session.fail()
            return session, 2
        console.print(f"[cyan]→ Running module[/cyan] {module.name} with {len(payloads)} payloads")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            bar = progress.add_task("payloads", total=len(payloads))

            def on_progress(done: int, total: int, payload, hit: bool) -> None:
                progress.update(bar, completed=done)
                if hit:
                    console.print(f"   [bold red]HIT[/bold red] {payload.id} ({payload.technique})")

            await module.run(
                target=client,
                payloads=payloads,
                session=session,
                concurrency=concurrency,
                rate_limit=rate_limit,
                canary=canary,
                progress=on_progress,
            )

    session.complete()
    write_report(session.state, session.report_path, target_url=target)
    console.print(f"[green]✓[/green] Report: {session.report_path}")
    console.print(f"[green]✓[/green] State : {session.json_path}")
    _print_summary(session)
    return session, 0


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target endpoint URL."),
    module_name: str = typer.Option("prompt-injection", "--module", help="Module to run."),
    gen: str = typer.Option("static", "--gen", help="Payload generator: static | ollama."),
    concurrency: int = typer.Option(5, "--concurrency", help="Parallel requests in flight."),
    rate_limit: float = typer.Option(5.0, "--rate-limit", help="Max requests/sec per worker."),
    output_dir: Path = typer.Option(Path("./engagements"), "--output-dir", help="Where to write engagement dirs."),
    canary: str = typer.Option("COBALT_LAB_2026", "--canary", help="Canary substring to flag in responses."),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings", help="Exit 1 if any findings (for CI)."),
    body_template: str | None = typer.Option(None, "--body-template", help='JSON body template with {payload} placeholder.'),
    response_path: str = typer.Option("response", "--response-path", help='Dot-path to LLM text in JSON response.'),
    payload_placeholder: str = typer.Option("{payload}", "--payload-placeholder", help="Placeholder in body template."),
    method: str = typer.Option("POST", "--method", help="HTTP method."),
    headers: str | None = typer.Option(None, "--headers", help="Semicolon-separated key:val list."),
    timeout: float = typer.Option(15.0, "--timeout", help="Per-request timeout (seconds)."),
    ollama_host: str | None = typer.Option(None, "--ollama-host", help="Ollama base URL (only when --gen ollama)."),
    ollama_model: str | None = typer.Option(None, "--ollama-model", help="Ollama model tag (only when --gen ollama)."),
    variants_per_seed: int | None = typer.Option(None, "--variants-per-seed", help="Ollama: variants generated per seed payload."),
    max_payloads: int | None = typer.Option(None, "--max-payloads", help="Cap total payloads per scan (after generation). Useful for cost-controlled API targets."),
) -> None:
    """Run a scan against an LLM-integrated endpoint."""
    output_dir.mkdir(parents=True, exist_ok=True)
    target_cfg = _build_target_config(
        target=target,
        body_template=body_template,
        response_path=response_path,
        payload_placeholder=payload_placeholder,
        method=method,
        headers=headers,
        timeout=timeout,
    )

    session, exit_code = asyncio.run(
        _scan_async(
            target=target,
            module_name=module_name,
            gen_name=gen,
            concurrency=concurrency,
            rate_limit=rate_limit,
            output_dir=output_dir,
            canary=canary,
            target_cfg=target_cfg,
            ollama_host=ollama_host,
            ollama_model=ollama_model,
            variants_per_seed=variants_per_seed,
            max_payloads=max_payloads,
        )
    )

    if exit_code != 0:
        raise typer.Exit(code=exit_code)
    if fail_on_findings and session.state.findings:
        raise typer.Exit(code=1)


@app.command()
def report(
    engagement: Path = typer.Option(..., "--engagement", "-e", help="Path to an engagement directory."),
    target_url: str | None = typer.Option(None, "--target", help="Override target URL in the report header."),
) -> None:
    """Re-render report.md from a stored engagement.json."""
    if not engagement.is_dir():
        console.print(f"[red]Not a directory: {engagement}[/red]")
        raise typer.Exit(code=2)
    session = EngagementSession.load(engagement)
    write_report(session.state, session.report_path, target_url=target_url or session.state.target)
    console.print(f"[green]✓[/green] Report regenerated: {session.report_path}")


@app.command()
def version() -> None:
    """Print Merlin version."""
    console.print(f"merlin {__version__}")


if __name__ == "__main__":
    app()
