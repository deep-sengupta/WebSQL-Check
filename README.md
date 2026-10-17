# WebSQL-Check

> A lightweight Python tool for detecting possible SQL injection vulnerabilities in web requests.

## What it does

WebSQL-Check tests common request inputs using:

* Error-based detection
* Boolean-based detection
* Time-based detection
* Union-based detection

It can check query parameters, form data, JSON, XML, paths, and headers.

## Install

```bash
pip install -r requirements.txt
```

## Quick Start

Scan URLs from a file:

```bash
python websql_check.py -f urls.txt
```

Scan from stdin:

```bash
cat urls.txt | python websql_check.py --stdin
```

Create a report:

```bash
python websql_check.py -f urls.txt -o report.json --format json
```

Supported report formats: `json`, `csv`, `html`

### Scope and redirects

* By default WebSQL Check only talks to the hosts of the targets you give it. Redirects to any other host are **not** followed.
* `--scope` takes host names (`example.com`), wildcards (`*.example.com`, subdomains only), `host:port`, IPs or CIDR ranges
  (`10.0.0.0/24`), comma separated or repeated. It is matched against the host name only, never against paths or query strings,
  and it is not a regex.
* Credentials you pass with `-H` (Authorization, Cookie, API keys, ...) are never sent to a different origin, even if it is in scope.
* Responses are truncated after `--max-response-bytes` (default 2 MiB) and each request has a wall-clock deadline of
  `max(3 x --timeout, 5)` seconds.

## Useful Options

```text
--techniques error,boolean,time,union
-m POST
-H "Authorization: Bearer ..."
-p http://127.0.0.1:8080
-w 10
-t 10
--scope "example.com,*.example.com"
--max-response-bytes 2097152
```

For all options:

```bash
python websql_check.py -h
```

## Example

Create `urls.txt`:

```text
https://example.com/page?id=1
https://example.com/product?id=2
```

Then run:

```bash
python websql_check.py -f urls.txt
```

## Safety

Use WebSQL-Check only on systems you own or have explicit permission to test.
