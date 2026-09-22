import csv
import html
import json
from pathlib import Path

class Reporter:
    def __init__(self, findings):
        self.findings = findings

    def records(self):
        return [{"technique": f.technique, "parameter": f.parameter, "payload": f.payload, "url": f.url, "confidence": f.confidence, "score": round(f.score, 4), "evidence": f.evidence} for f in self.findings]

    def write(self, path: str, fmt: str = "json"):
        p = Path(path)
        fmt = fmt.lower()
        if fmt == "json":
            p.write_text(json.dumps(self.records(), indent=2), encoding="utf-8")
            return
        if fmt == "csv":
            rows = self.records()
            with p.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["technique", "parameter", "payload", "url", "confidence", "score", "evidence"])
                writer.writeheader()
                for row in rows:
                    row["evidence"] = json.dumps(row["evidence"], ensure_ascii=False)
                    writer.writerow(row)
            return
        if fmt == "html":
            body = "".join(f"<tr><td>{html.escape(str(x['technique']))}</td><td>{html.escape(str(x['parameter']))}</td><td>{html.escape(str(x['url']))}</td><td>{html.escape(str(x['confidence']))}</td><td>{x['score']}</td><td><pre>{html.escape(json.dumps(x['evidence'], indent=2))}</pre></td></tr>" for x in self.records())
            page = "<!doctype html><html><head><meta charset='utf-8'><title>WebSQL Check Report</title><style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.5rem;text-align:left;vertical-align:top}pre{white-space:pre-wrap}</style></head><body><h1>WebSQL Check Report</h1><table><thead><tr><th>Technique</th><th>Parameter</th><th>URL</th><th>Confidence</th><th>Score</th><th>Evidence</th></tr></thead><tbody>" + body + "</tbody></table></body></html>"
            p.write_text(page, encoding="utf-8")
            return
        raise ValueError("Unsupported report format")
