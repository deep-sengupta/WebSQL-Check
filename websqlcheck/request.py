from dataclasses import dataclass
import json
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import re

@dataclass
class Target:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    body: str = ""
    content_type: str = ""

    def __post_init__(self):
        self.headers = dict(self.headers or {})
        if not self.content_type:
            self.content_type = self.headers.get("Content-Type", "")


def parse_headers(value: str) -> Dict[str, str]:
    result = {}
    for item in re.split(r"\\n|\n", value or ""):
        if not item.strip() or ":" not in item:
            continue
        k, v = item.split(":", 1)
        result[k.strip()] = v.strip().rstrip(",")
    return result


def parse_raw_request(path: str, base_url: str) -> Target:
    raw = open(path, "r", encoding="utf-8", errors="ignore").read().replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("Invalid request file")
    first = lines[0].split()
    if len(first) < 2:
        raise ValueError("Invalid request line")
    method = first[0].upper()
    target = first[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        if not base_url:
            raise ValueError("--base-url is required when the request target is relative")
        url = base_url.rstrip("/") + "/" + target.lstrip("/")
    return Target(url=url, method=method, headers=headers, body=body, content_type=headers.get("Content-Type", ""))


def split_target(target: Target) -> List[Tuple[str, str, str]]:
    parts = urlsplit(target.url)
    return parse_qsl(parts.query, keep_blank_values=True)


def mutate_query(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    params[index] = (params[index][0], value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params, doseq=True), parts.fragment))



def mutate_path(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    segments = parts.path.split("/")
    segments[index] = value
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))

def mutate_form(body: str, index: int, value: str) -> str:
    params = parse_qsl(body, keep_blank_values=True)
    params[index] = (params[index][0], value)
    return urlencode(params, doseq=True)


def flatten_json(data, path=()):
    if isinstance(data, dict):
        for key, value in data.items():
            yield from flatten_json(value, path + (key,))
    elif isinstance(data, list):
        for i, value in enumerate(data):
            yield from flatten_json(value, path + (i,))
    else:
        yield path, data


def set_json_path(data, path, value):
    current = data
    for item in path[:-1]:
        current = current[item]
    current[path[-1]] = value
    return data


def mutate_json(body: str, path, value: str) -> str:
    data = json.loads(body)
    set_json_path(data, path, value)
    return json.dumps(data, separators=(",", ":"))


def mutate_xml(body: str, token: str, value: str) -> str:
    pattern = r">(\s*)" + re.escape(token) + r"(\s*)<"
    return re.sub(pattern, lambda m: ">" + m.group(1) + value + m.group(2) + "<", body, count=1)
