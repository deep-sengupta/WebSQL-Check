from dataclasses import dataclass, field
import re
from statistics import median
from difflib import SequenceMatcher
from .data import ERROR_SIGNATURES, BOOLEAN_PAYLOADS, TIME_PAYLOADS, GENERIC_TIME_PAYLOADS, UNION_PAYLOADS
from pathlib import Path
from .http import HttpClient, HttpResult, timing_threshold

@dataclass
class Finding:
    technique: str
    parameter: str
    payload: str
    url: str
    confidence: str
    score: float
    evidence: dict = field(default_factory=dict)


def response_similarity(a: HttpResult, b: HttpResult) -> float:
    if a.status != b.status:
        return 0.0
    if not a.body and not b.body:
        return 1.0
    if not a.body or not b.body:
        return 0.0
    return SequenceMatcher(None, a.body, b.body, autojunk=False).ratio()


def changed(a: HttpResult, b: HttpResult) -> float:
    length_component = min(abs(len(a.body) - len(b.body)) / max(len(a.body), 1), 1.0)
    sim_component = 1.0 - response_similarity(a, b)
    status_component = 1.0 if a.status != b.status else 0.0
    return min(1.0, length_component * 0.5 + sim_component * 0.4 + status_component * 0.1)

class ErrorDetector:
    def __init__(self):
        path = Path(__file__).resolve().parent / "sql_errors.txt"
        self.patterns = [x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]

    def detect(self, result: HttpResult, parameter: str, payload: str) -> list[Finding]:
        findings = []
        matched = []
        dbs = []
        for pattern in self.patterns:
            try:
                if re.search(pattern, result.body, re.I | re.M):
                    matched.append(pattern)
            except re.error:
                continue
        for db, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, result.body, re.I | re.M):
                        dbs.append(db)
                except re.error:
                    continue
        if matched:
            unique_dbs = list(dict.fromkeys(dbs))
            findings.append(Finding("error", parameter, payload, result.url, "high", min(1.0, 0.65 + len(matched) * 0.03), {"matched_patterns": matched[:12], "database_guesses": unique_dbs}))
        return findings

class BooleanDetector:
    def detect(self, client: HttpClient, baseline: HttpResult, request_fn, parameter: str) -> list[Finding]:
        findings = []
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_result = request_fn(true_payload)
            false_result = request_fn(false_payload)
            if true_result.error or false_result.error:
                continue
            true_delta = changed(baseline, true_result)
            false_delta = changed(baseline, false_result)
            pair_delta = abs(true_delta - false_delta)
            sim = response_similarity(true_result, false_result)
            true_len = len(true_result.body)
            false_len = len(false_result.body)
            ratio = abs(true_len - false_len) / max(max(true_len, false_len), 1)
            score = min(1.0, pair_delta * 1.5 + ratio * 0.8 + (1.0 - sim) * 0.8)
            if score >= 0.58:
                findings.append(Finding("boolean", parameter, f"{true_payload} | {false_payload}", true_result.url, "medium" if score < 0.8 else "high", score, {"true_status": true_result.status, "false_status": false_result.status, "true_length": true_len, "false_length": false_len, "true_false_similarity": round(sim, 4)}))
                break
        return findings

class TimeDetector:
    def detect(self, baseline_samples, request_fn, parameter: str, delay: int = 4, db_hint: str = "") -> list[Finding]:
        threshold = timing_threshold(baseline_samples)
        candidates = TIME_PAYLOADS.get(db_hint, []) + GENERIC_TIME_PAYLOADS
        findings = []
        for template in candidates:
            payload = template.format(delay=delay)
            samples = []
            last = None
            for _ in range(2):
                result = request_fn(payload)
                last = result
                if result.error:
                    break
                samples.append(result.elapsed)
            if len(samples) < 2:
                continue
            observed = median(samples)
            baseline = median(baseline_samples) if baseline_samples else 0.0
            delta = observed - baseline
            if observed >= threshold and delta >= max(2.0, delay * 0.55):
                score = min(1.0, 0.6 + min(0.4, delta / max(delay, 1) * 0.2))
                findings.append(Finding("time", parameter, payload, last.url if last else "", "high" if score >= 0.8 else "medium", score, {"baseline_median": round(baseline, 4), "observed_median": round(observed, 4), "delay_seconds": delay}))
                break
        return findings

class UnionDetector:
    def detect(self, baseline: HttpResult, request_fn, parameter: str) -> list[Finding]:
        findings = []
        base_length = len(baseline.body)
        for payload in UNION_PAYLOADS:
            result = request_fn(payload)
            if result.error:
                continue
            delta = changed(baseline, result)
            len_delta = abs(len(result.body) - base_length) / max(base_length, 1)
            score = min(1.0, delta * 1.3 + min(len_delta, 1.0) * 0.7)
            if score >= 0.82:
                findings.append(Finding("union", parameter, payload, result.url, "medium", score, {"baseline_status": baseline.status, "response_status": result.status, "baseline_length": base_length, "response_length": len(result.body)}))
                break
        return findings

class DatabaseFingerprint:
    def identify(self, body: str):
        matches = {}
        for db, patterns in ERROR_SIGNATURES.items():
            count = 0
            for pattern in patterns:
                try:
                    if re.search(pattern, body, re.I | re.M):
                        count += 1
                except re.error:
                    pass
            if count:
                matches[db] = count
        return sorted(matches.items(), key=lambda x: x[1], reverse=True)
