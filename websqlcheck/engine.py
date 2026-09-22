from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlsplit
import json
import re
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.console import Console
from .request import Target, split_target, mutate_query, mutate_form, flatten_json, mutate_json, mutate_path, mutate_xml
from .http import HttpClient
from .detectors import ErrorDetector, BooleanDetector, TimeDetector, UnionDetector, DatabaseFingerprint, Finding

@dataclass
class ScanConfig:
    method: str = "GET"
    body: str = ""
    content_type: str = ""
    workers: int = 10
    timeout: int = 10
    proxy: str = ""
    retries: int = 1
    rate: float = 0.0
    verify_tls: bool = True
    techniques: tuple = ("error", "boolean", "time", "union")
    delay: int = 4
    baseline_requests: int = 3
    scope: str = ""

class Scanner:
    def __init__(self, config: ScanConfig, headers=None):
        self.config = config
        self.headers = headers or {}
        self.console = Console()
        self.findings = []
        self.error_detector = ErrorDetector()
        self.boolean_detector = BooleanDetector()
        self.time_detector = TimeDetector()
        self.union_detector = UnionDetector()
        self.fingerprinter = DatabaseFingerprint()

    def in_scope(self, url):
        if not self.config.scope:
            return True
        return re.search(self.config.scope, url) is not None

    def build_client(self, target_headers=None):
        merged = dict(self.headers)
        merged.update(target_headers or {})
        return HttpClient(self.config.timeout, self.config.proxy or None, merged, self.config.retries, self.config.rate, self.config.verify_tls)

    def parameter_jobs(self, target: Target):
        jobs = []
        query = split_target(target)
        for index, (name, value) in enumerate(query):
            jobs.append(("query", name, value, index))
        content = target.content_type.lower()
        if target.body and "application/x-www-form-urlencoded" in content:
            for index, (name, value) in enumerate(parse_qsl(target.body, keep_blank_values=True)):
                jobs.append(("form", name, value, index))
        raw_path = urlsplit(target.url).path.split("/")
        for index, value in enumerate(raw_path):
            if value:
                jobs.append(("path", f"path[{index}]", value, index))
        for header_name, header_value in target.headers.items():
            if header_name.lower() in {"host", "content-length", "user-agent"}:
                continue
            jobs.append(("header", header_name, header_value, header_name))
        if target.body and "application/json" in content:
            try:
                data = json.loads(target.body)
                for path, value in flatten_json(data):
                    if isinstance(value, (str, int, float)):
                        jobs.append(("json", ".".join(map(str, path)), str(value), path))
            except (ValueError, TypeError):
                pass
        if target.body and ("xml" in content or "application/soap" in content):
            for match in re.finditer(r">([^<>]+)<", target.body):
                value = match.group(1).strip()
                if value:
                    jobs.append(("xml", f"xml[{match.start()}]", value, value))
        return jobs

    def request_fn(self, client, target, kind, name, original, index, payload):
        if kind == "query":
            url = mutate_query(target.url, index, original + payload)
            return client.request(target.method, url, data=target.body if target.body else None)
        if kind == "form":
            body = mutate_form(target.body, index, original + payload)
            return client.request(target.method, target.url, data=body, headers={"Content-Type": target.content_type or "application/x-www-form-urlencoded"})
        if kind == "json":
            body = mutate_json(target.body, index, original + payload)
            return client.request(target.method, target.url, data=body, headers={"Content-Type": target.content_type or "application/json"})
        if kind == "path":
            url = mutate_path(target.url, index, original + payload)
            return client.request(target.method, url, data=target.body or None)
        if kind == "header":
            headers = dict(target.headers)
            headers[index] = original + payload
            return client.request(target.method, target.url, data=target.body or None, headers=headers)
        if kind == "xml":
            body = mutate_xml(target.body, index, original + payload)
            return client.request(target.method, target.url, data=body, headers={"Content-Type": target.content_type or "application/xml"})
        return client.request(target.method, target.url, data=target.body or None)

    def scan_parameter(self, target, job):
        kind, name, original, index = job
        client = self.build_client(target.headers)
        baseline_samples = []
        baseline_result = None
        for _ in range(max(1, self.config.baseline_requests)):
            result = client.request(target.method, target.url, data=target.body or None)
            if result.error:
                return []
            baseline_result = result
            baseline_samples.append(result.elapsed)
        findings = []
        fingerprint = self.fingerprinter.identify(baseline_result.body if baseline_result else "")
        db_hint = fingerprint[0][0] if fingerprint else ""
        request_with_payload = lambda payload: self.request_fn(client, target, kind, name, original, index, payload)
        if "error" in self.config.techniques:
            for payload in ["'123", "''123", "`123", '")123', '"))123', "`)123", "`))123", "'))123", "')123\"123", "[]123", '\"\"123', "'\"123", '\"\'123', "\\123"]:
                result = request_with_payload(payload)
                if result.error:
                    continue
                findings.extend(self.error_detector.detect(result, name, payload))
                if findings:
                    break
        if "boolean" in self.config.techniques:
            findings.extend(self.boolean_detector.detect(client, baseline_result, request_with_payload, name))
        if "time" in self.config.techniques:
            findings.extend(self.time_detector.detect(baseline_samples, request_with_payload, name, self.config.delay, db_hint))
        if "union" in self.config.techniques:
            findings.extend(self.union_detector.detect(baseline_result, request_with_payload, name))
        return findings

    def scan(self, targets):
        jobs = []
        for target in targets:
            if not self.in_scope(target.url):
                continue
            jobs.extend((target, job) for job in self.parameter_jobs(target))
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn()) as progress:
            task = progress.add_task("Scanning", total=len(jobs))
            with ThreadPoolExecutor(max_workers=max(1, self.config.workers)) as pool:
                futures = [pool.submit(self.scan_parameter, target, job) for target, job in jobs]
                for future in as_completed(futures):
                    try:
                        results = future.result()
                    except Exception:
                        results = []
                    self.findings.extend(results)
                    progress.advance(task)
        return self.findings
