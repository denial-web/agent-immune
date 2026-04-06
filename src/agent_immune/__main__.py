"""CLI entry point: ``python -m agent_immune`` or ``agent-immune``."""

from __future__ import annotations

import argparse
import json
import sys

from agent_immune import AdaptiveImmuneSystem, ThreatAction, __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-immune",
        description="Assess text for prompt injection and data exfiltration threats.",
    )
    p.add_argument("--version", action="version", version=f"agent-immune {__version__}")

    sub = p.add_subparsers(dest="command")

    assess = sub.add_parser("assess", help="Assess input text for injection threats")
    assess.add_argument("text", nargs="?", help="Text to assess (reads stdin if omitted)")
    assess.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")

    scan = sub.add_parser("scan-output", help="Scan output text for data exfiltration")
    scan.add_argument("text", nargs="?", help="Text to scan (reads stdin if omitted)")
    scan.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")

    serve = sub.add_parser(
        "serve",
        help="Run agent-immune as a local MCP server (requires: pip install 'agent-immune[mcp]')",
    )
    serve.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http", "http"),
        default="stdio",
        help="MCP transport: stdio (default), sse, streamable-http, or http (alias for streamable-http)",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=8000,
        metavar="N",
        help="TCP port for sse / streamable-http / http (ignored for stdio; default: 8000)",
    )

    return p


def _read_text(text: str | None) -> str:
    if text is not None:
        return text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("Error: provide text as an argument or pipe via stdin.", file=sys.stderr)
    sys.exit(1)


def _action_color(action: ThreatAction) -> str:
    colors = {
        ThreatAction.ALLOW: "\033[32m",
        ThreatAction.SANITIZE: "\033[33m",
        ThreatAction.REVIEW: "\033[33m",
        ThreatAction.BLOCK: "\033[31m",
    }
    reset = "\033[0m"
    return f"{colors.get(action, '')}{action.value.upper()}{reset}"


def cmd_assess(args: argparse.Namespace) -> None:
    text = _read_text(args.text)
    immune = AdaptiveImmuneSystem()
    result = immune.assess(text)

    if args.as_json:
        print(json.dumps({
            "action": result.action.value,
            "threat_score": round(result.threat_score, 4),
            "pattern_score": round(result.pattern_score, 4),
            "feedback": result.feedback,
        }, indent=2))
    else:
        print(f"Action:       {_action_color(result.action)}")
        print(f"Threat score: {result.threat_score:.4f}")
        print(f"Pattern score:{result.pattern_score:.4f}")
        if result.feedback:
            print(f"Feedback:     {'; '.join(result.feedback)}")


def cmd_serve(args: argparse.Namespace) -> None:
    from agent_immune.mcp_server import run_mcp_server

    run_mcp_server(transport=args.transport, port=args.port)


def cmd_scan_output(args: argparse.Namespace) -> None:
    text = _read_text(args.text)
    immune = AdaptiveImmuneSystem()
    result = immune.assess_output(text)

    if args.as_json:
        print(json.dumps({
            "exfiltration_score": round(result.exfiltration_score, 4),
            "contains_pii": result.contains_pii,
            "contains_credentials": result.contains_credentials,
            "contains_system_prompt_leak": result.contains_system_prompt_leak,
            "findings": result.findings,
        }, indent=2))
    else:
        print(f"Exfiltration score: {result.exfiltration_score:.4f}")
        print(f"PII detected:       {result.contains_pii}")
        print(f"Credentials:        {result.contains_credentials}")
        print(f"Prompt leak:        {result.contains_system_prompt_leak}")
        if result.findings:
            print(f"Findings:           {', '.join(result.findings)}")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "assess":
        cmd_assess(args)
    elif args.command == "scan-output":
        cmd_scan_output(args)
    elif args.command == "serve":
        cmd_serve(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
