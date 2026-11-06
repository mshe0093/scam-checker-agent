"""Command line: run the full agent, or a single tool without an API key."""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scamcheck.models import ToolResult
from scamcheck.registry import run_tool

app = typer.Typer(add_completion=False, help="Agentic scam/phishing message checker for Malaysia.")
console = Console()

_SEV = {"red": "bold red", "amber": "yellow", "green": "green", "info": "dim"}
_VERDICT = {
    "likely_scam": ("LIKELY SCAM", "bold white on red"),
    "suspicious": ("SUSPICIOUS", "bold black on yellow"),
    "likely_legitimate": ("LIKELY LEGITIMATE", "bold white on green"),
    "insufficient_information": ("NOT ENOUGH INFORMATION", "bold white on blue"),
}
_OUTCOME = {
    "fail": "[red]✗[/]",
    "warn": "[yellow]![/]",
    "pass": "[green]✓[/]",
    "unverified": "[dim]?[/]",
}


def _read_message(message: str | None) -> str:
    if message and message != "-":
        return message
    if sys.stdin.isatty():
        console.print("[dim]Paste the message, then Ctrl-D (Ctrl-Z Enter on Windows):[/]")
    return sys.stdin.read().strip()


def _print_result(res: ToolResult) -> None:
    style = {"ok": "green", "unverified": "yellow", "error": "red"}[res.status.value]
    console.print(f"  [{style}]{res.status.value}[/] {res.summary}")
    for s in res.signals:
        console.print(f"    [{_SEV[s.severity.value]}]● {s.severity.value}[/] {s.detail}")


def _print_verdict(v: dict) -> None:
    label, style = _VERDICT.get(v["verdict"], (v["verdict"], "bold"))
    console.print()
    console.print(
        Panel(
            f"[{style}] {label} [/] ({v['confidence']} confidence)\n\n{v['headline']}",
            title="Verdict",
            expand=False,
        )
    )
    if v.get("floor_applied"):
        console.print(
            "[yellow]Verdict floor applied:[/] the model said likely_legitimate, but "
            "deterministic red flags exist:"
        )
        for r in v["floor_applied"]["reasons"]:
            console.print(f"  - {r}")
    table = Table(show_header=False, box=None, padding=(0, 1))
    for f in v.get("findings", []):
        table.add_row(_OUTCOME.get(f["outcome"], "?"), f"[bold]{f['check']}[/]", f["detail"])
    console.print(table)
    if v.get("recommended_actions"):
        console.print("\n[bold]What to do[/]")
        for a in v["recommended_actions"]:
            console.print(f"  • {a}")


@app.command()
def check(
    message: Annotated[
        str | None, typer.Argument(help="Message text, or '-' / omit for stdin")
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Print the event stream as JSON lines")
    ] = False,
    interactive: Annotated[
        bool, typer.Option("-i", help="Ask follow-up questions afterwards")
    ] = False,
) -> None:
    """Investigate a suspicious message with the full agent (needs ANTHROPIC_API_KEY)."""
    from scamcheck.agent import ScamCheckAgent

    text = _read_message(message)
    if not text:
        raise typer.BadParameter("empty message")
    agent = ScamCheckAgent()
    _render(agent.check(text), as_json)
    while interactive:
        q = console.input("\n[bold cyan]Follow-up (blank to quit)> [/]").strip()
        if not q:
            break
        _render(agent.ask(q), as_json)


def _render(events, as_json: bool) -> None:
    for ev in events:
        if as_json:
            print(json.dumps(ev, default=str))
            continue
        kind = ev["type"]
        if kind == "tool_call":
            args = ", ".join(f"{k}={v!r}"[:80] for k, v in ev["input"].items())
            console.print(f"[cyan]→ {ev['name']}[/]({args})")
        elif kind == "tool_result":
            _print_result(ToolResult.model_validate(ev["result"]))
        elif kind == "text":
            console.print(f"[italic]{ev['text']}[/]")
        elif kind == "verdict":
            _print_verdict(ev["verdict"])
        elif kind == "error":
            console.print(f"[red]Error:[/] {ev['message']}")
        elif kind == "done":
            u = ev["usage"]
            console.print(
                f"\n[dim]{u['model_calls']} model call(s), {u['tool_calls']} tool call(s), "
                f"{u['input_tokens']} in / {u['output_tokens']} out tokens[/]"
            )


TOOL_ALIASES = {
    "entities": ("extract_entities", "message"),
    "domain": ("check_domain", "domain_or_url"),
    "redirects": ("resolve_url_redirects", "url"),
    "contact": ("lookup_official_contact", "org_name"),
    "pattern": ("match_scam_pattern", "message"),
    "phone": ("check_phone_number", "number"),
}


@app.command()
def tool(
    name: Annotated[
        str, typer.Argument(help="entities | domain | redirects | contact | pattern | phone")
    ],
    value: Annotated[str, typer.Argument(help="The input for the tool")],
    claimed_org: Annotated[
        str, typer.Option(help="For 'domain': org the message claims to be")
    ] = "",
) -> None:
    """Run one verification tool directly (no LLM, no API key)."""
    if name not in TOOL_ALIASES:
        raise typer.BadParameter(f"choose one of {', '.join(TOOL_ALIASES)}")
    tool_name, arg = TOOL_ALIASES[name]
    args = {arg: value}
    if tool_name == "check_domain":
        args["claimed_org"] = claimed_org
    res = run_tool(tool_name, args)
    console.print(f"[cyan]{tool_name}[/]")
    _print_result(res)
    console.print_json(json.dumps(res.evidence, default=str))


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port")] = 8000,
) -> None:
    """Run the HTTP API (SSE streaming) with uvicorn."""
    import uvicorn

    from scamcheck.api import create_app

    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
