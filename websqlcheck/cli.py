import argparse
from pathlib import Path
from rich.console import Console
from rich.text import Text
from .engine import Scanner, ScanConfig
from .request import Target, parse_headers, parse_raw_request
from .report import Reporter

console = Console()

LOGO = r"""
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██╗     
██║    ██║██╔════╝██╔══██╗██╔════╝██╔═══██╗██║     
██║ █╗ ██║█████╗  ██████╔╝███████╗██║   ██║██║     
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║▄▄ ██║██║     
╚███╔███╔╝███████╗██████╔╝███████║╚██████╔╝███████╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚══▀▀═╝ ╚══════╝
"""

def show_banner():
    console.print(Text(LOGO, style="bold white"))
    console.print(Text("Usage: websql_check -f urls.txt [options]", style="dim white"))
    console.print("[dim white]Help: websql_check -h\n[/dim white]")

def build_parser():
    p = argparse.ArgumentParser(prog="websql_check", description="SQL injection detection toolkit")
    p.add_argument("-f", "--file")
    p.add_argument("--stdin", action="store_true")
    p.add_argument("--request-file")
    p.add_argument("--base-url")
    p.add_argument("-m", "--method", default="GET")
    p.add_argument("-d", "--data", default="")
    p.add_argument("--content-type", default="application/x-www-form-urlencoded")
    p.add_argument("-w", "--workers", type=int, default=10)
    p.add_argument("-p", "--proxy", default="")
    p.add_argument("-H", "--header", default="")
    p.add_argument("-t", "--timeout", type=int, default=10)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--rate", type=float, default=0.0)
    p.add_argument("--delay", type=int, default=4)
    p.add_argument("--baseline", type=int, default=3)
    p.add_argument("--techniques", default="error,boolean,time,union")
    p.add_argument("--scope", default="")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("-o", "--output")
    p.add_argument("--format", choices=["json", "csv", "html"], default="json")
    p.add_argument("--exit-on-find", action="store_true")
    return p

def load_targets(args):
    headers = parse_headers(args.header)
    if args.request_file:
        if not args.base_url:
            raise SystemExit("--base-url is required with --request-file when the request target is relative")
        target = parse_raw_request(args.request_file, args.base_url)
        return [target], headers
    targets = []
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line:
                targets.append(Target(line, args.method.upper(), headers, args.data, args.content_type))
    elif args.stdin:
        import sys
        for line in sys.stdin:
            line = line.strip()
            if line:
                targets.append(Target(line, args.method.upper(), headers, args.data, args.content_type))
    else:
        raise SystemExit("Provide --file, --stdin, or --request-file")
    return targets, headers

def main():
    parser = build_parser()
    show_banner()
    args = parser.parse_args()
    targets, headers = load_targets(args)
    techniques = tuple(x.strip().lower() for x in args.techniques.split(",") if x.strip())
    config = ScanConfig(method=args.method.upper(), body=args.data, content_type=args.content_type, workers=max(1, args.workers), timeout=max(1, args.timeout), proxy=args.proxy, retries=max(0, args.retries), rate=max(0.0, args.rate), verify_tls=not args.insecure, techniques=techniques, delay=max(2, args.delay), baseline_requests=max(1, args.baseline), scope=args.scope)
    scanner = Scanner(config, headers)
    findings = scanner.scan(targets)
    console.print(f"\n[bold]Findings:[/bold] {len(findings)}")
    for finding in findings:
        console.print(f"[red]{finding.technique.upper()}[/red] [bold]{finding.parameter}[/bold] {finding.confidence} {finding.url}")
    if args.output:
        Reporter(findings).write(args.output, args.format)
        console.print(f"[green]Report written:[/green] {args.output}")
    if args.exit_on_find and findings:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
