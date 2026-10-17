import argparse
from pathlib import Path
from rich.console import Console
from rich.text import Text
from .engine import Scanner, ScanConfig
from .http import DEFAULT_MAX_RESPONSE_BYTES
from .request import Target, parse_headers, parse_raw_request
from .report import Reporter
from .scope import Scope, ScopeError, split_url

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
    p.add_argument("--scope", action="append", default=[], metavar="HOSTS", help="hosts we may talk to, e.g. example.com, *.example.com, host:8443, 10.0.0.0/24 (comma separated or repeated). Default: only the hosts of the given targets. Redirects to any other host are not followed.")
    p.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES, help="keep at most this many bytes of each response (default: %(default)s)")
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

def render_finding(finding) -> Text:
    line = Text()
    line.append(finding.technique.upper(), style="red")
    line.append(" ")
    line.append(str(finding.parameter), style="bold")
    line.append(f" {finding.confidence} {finding.url}")
    return line

def check_output_path(parser, path):
    out = Path(path)
    if out.is_dir() or not out.parent.is_dir():
        parser.error(f"cannot write report to {path!r}: directory does not exist or path is a directory")

def main():
    parser = build_parser()
    show_banner()
    args = parser.parse_args()
    if args.output:
        check_output_path(parser, args.output)
    try:
        scope = Scope.parse(args.scope) if args.scope else None
    except ScopeError as exc:
        parser.error(str(exc))
    targets, headers = load_targets(args)
    valid = []
    for target in targets:
        if split_url(target.url) is None:
            console.print(Text.assemble(("Warning: ", "yellow"), f"skipping invalid target {target.url!r} (an absolute http:// or https:// URL is required)"))
        else:
            valid.append(target)
    targets = valid
    techniques = tuple(x.strip().lower() for x in args.techniques.split(",") if x.strip())
    config = ScanConfig(method=args.method.upper(), body=args.data, content_type=args.content_type, workers=max(1, args.workers), timeout=max(1, args.timeout), proxy=args.proxy, retries=max(0, args.retries), rate=max(0.0, args.rate), verify_tls=not args.insecure, techniques=techniques, delay=max(2, args.delay), baseline_requests=max(1, args.baseline), scope=scope, max_response_bytes=args.max_response_bytes)
    scanner = Scanner(config, headers)
    findings = scanner.scan(targets)
    if args.output:
        Reporter(findings).write(args.output, args.format)
    console.print(Text.assemble("\n", ("Findings: ", "bold"), str(len(findings))))
    for finding in findings:
        console.print(render_finding(finding), soft_wrap=True)
    if args.output:
        console.print(Text.assemble(("Report written: ", "green"), args.output))
    if args.exit_on_find and findings:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
