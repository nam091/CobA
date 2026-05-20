"""Typer CLI for CobA: scan / serve / doctor / models / eval."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from coba import __version__
from coba.agent.loop import Orchestrator
from coba.config.settings import get_settings
from coba.llm.cost import MODEL_PRICES
from coba.tools import BanditRunner, GitleaksRunner, JoernRunner, SemgrepRunner
from coba.utils.logging import configure_logging
from coba.utils.schemas import Language, ScanRequest

app = typer.Typer(
    name="coba",
    help="CobA — LLM-powered Source Code Vulnerability Analysis Agent",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.callback()
def _global_options(
    log_level: Annotated[str, typer.Option(help="Log level")] = "INFO",
    json_logs: Annotated[bool, typer.Option(help="Emit JSON logs")] = False,
) -> None:
    configure_logging(level=log_level, json_logs=json_logs)


@app.command("version")
def version_cmd() -> None:
    """Print CobA version."""
    console.print(f"CobA v{__version__}")


@app.command("scan")
def scan_cmd(
    target: Annotated[Path, typer.Argument(help="Path to source dir or file")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write report JSON here")
    ] = None,
    languages: Annotated[
        str | None,
        typer.Option(help="Comma-separated languages, e.g. python,java"),
    ] = None,
    profile: Annotated[str, typer.Option(help='"fast" or "accuracy"')] = "fast",
    no_cloud: Annotated[bool, typer.Option(help="Disable cloud LLMs")] = False,
) -> None:
    """Run a CobA scan on a local path."""
    consent = "You confirm you have permission to scan this code. Proceed? [y/N] "
    if not target.exists():
        console.print(f"[red]Path not found:[/red] {target}")
        raise typer.Exit(2)

    langs: list[Language] | None = None
    if languages:
        langs = [Language(s.strip().lower()) for s in languages.split(",") if s.strip()]

    request = ScanRequest(
        target_path=str(target),
        languages=langs,
        profile=profile,
        no_cloud=no_cloud,
    )
    orch = Orchestrator()
    report = asyncio.run(orch.scan(request))

    _print_report(report)
    if output:
        output.write_text(report.model_dump_json(indent=2))
        console.print(f"[green]Report written to[/green] {output}")
    _ = consent  # placeholder for future interactive consent prompt


@app.command("serve")
def serve_cmd(
    host: Annotated[str, typer.Option(help="Bind host")] = "0.0.0.0",
    port: Annotated[int, typer.Option(help="Bind port")] = 8000,
) -> None:
    """Run the FastAPI server."""
    import uvicorn

    uvicorn.run("coba.api.app:app", host=host, port=port, log_level="info")


@app.command("doctor")
def doctor_cmd() -> None:
    """Check tool availability and configuration."""
    s = get_settings()
    table = Table(title="CobA doctor")
    table.add_column("Component")
    table.add_column("Detail")
    table.add_column("Status")

    table.add_row("Python", "interpreter", "ok")

    for tool in (SemgrepRunner(), BanditRunner(), GitleaksRunner(), JoernRunner()):
        on_path = bool(shutil.which(tool.binary))
        table.add_row(f"tool:{tool.name}", tool.binary, "ok" if on_path else "MISSING")

    table.add_row("LLM:openai", "OPENAI_API_KEY", "set" if s.openai_api_key else "not set")
    table.add_row("LLM:anthropic", "ANTHROPIC_API_KEY", "set" if s.anthropic_api_key else "not set")
    table.add_row("LLM:google", "GOOGLE_API_KEY", "set" if s.google_api_key else "not set")
    table.add_row("LLM:ollama", s.ollama_base_url, "(check via /api/tags)")

    console.print(table)


@app.command("models")
def models_cmd() -> None:
    """List supported models and prices."""
    s = get_settings()
    console.print(f"[bold]Detector:[/bold] {s.coba_llm_detector}")
    console.print(f"[bold]Verifier:[/bold] {s.coba_llm_verifier}")
    console.print(f"[bold]Offline fallback:[/bold] {s.coba_llm_offline_fallback}")
    table = Table(title="Supported models")
    table.add_column("Model")
    table.add_column("Input $/1M", justify="right")
    table.add_column("Output $/1M", justify="right")
    for m, p in MODEL_PRICES.items():
        table.add_row(m, f"{p.input_per_million:.3f}", f"{p.output_per_million:.3f}")
    console.print(table)


@app.command("eval")
def eval_cmd(
    dataset: Annotated[str, typer.Option(help="primevul | owasp | juliet")] = "primevul",
    subset: Annotated[int, typer.Option(help="N examples")] = 100,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("benchmarks/results"),
) -> None:
    """Run evaluation (stub for v0)."""
    output.mkdir(parents=True, exist_ok=True)
    console.print(f"[yellow]eval stub:[/yellow] dataset={dataset} subset={subset} → {output}")
    console.print("Run `make download-datasets` first, then implement in M4.")


def _print_report(report) -> None:
    console.print(f"\n[bold]Scan {report.scan_id}[/bold]")
    console.print(f"Target: {report.target}")
    if report.stats:
        s = report.stats
        console.print(
            f"Files: {s.n_files} · Chunks: {s.n_chunks} · "
            f"Static: {s.n_static_findings} · Raw: {s.n_raw_findings} · "
            f"Final: {s.n_final_findings} · Cost: ${s.total_cost_usd:.4f}"
        )
    if report.findings:
        table = Table(title="Findings")
        table.add_column("CWE")
        table.add_column("Severity")
        table.add_column("Conf", justify="right")
        table.add_column("File:line")
        table.add_column("Title")
        for f in report.findings:
            table.add_row(
                f.cwe,
                f.severity.value,
                f"{f.confidence:.2f}",
                f"{f.file}:{f.line_start}",
                f.title,
            )
        console.print(table)
    else:
        console.print("[green]No vulnerabilities found.[/green]")


if __name__ == "__main__":  # pragma: no cover
    app()
