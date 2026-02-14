#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import Counter, defaultdict

CRITICAL_PATTERNS = (
    re.compile(r"TLS13", re.IGNORECASE),
    re.compile(r"HRR", re.IGNORECASE),
    re.compile(r"KeyUpdate", re.IGNORECASE),
    re.compile(r"EarlyData", re.IGNORECASE),
    re.compile(r"Resumption", re.IGNORECASE),
)


def is_critical_test(name: str) -> bool:
    return any(p.search(name) for p in CRITICAL_PATTERNS)


def summarize(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    tests = data.get("tests", []) if isinstance(data, dict) else []
    status_counter = Counter()
    suite_counter = defaultdict(Counter)
    critical_failures = []

    for t in tests:
        name = t.get("name", "unknown")
        status = t.get("result", "unknown").lower()
        suite = name.split("/")[0] if "/" in name else "misc"
        status_counter[status] += 1
        suite_counter[suite][status] += 1
        if status == "fail" and is_critical_test(name):
            critical_failures.append(name)

    return {
        "total": sum(status_counter.values()),
        "status": dict(status_counter),
        "suites": {k: dict(v) for k, v in sorted(suite_counter.items())},
        "critical_failures": sorted(critical_failures),
        "critical_failure_count": len(critical_failures),
    }


def self_test() -> int:
    sample = {
        "tests": [
            {"name": "TLS13/BasicHandshake", "result": "PASS"},
            {"name": "TLS13/HRR", "result": "FAIL"},
            {"name": "Record/Overflow", "result": "PASS"},
        ]
    }
    path = "/tmp/zigtls-bogo-selftest.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sample, f)

    out = summarize(path)
    assert out["total"] == 3
    assert out["status"].get("pass") == 2
    assert out["status"].get("fail") == 1
    assert out["critical_failure_count"] == 1
    assert out["critical_failures"][0] == "TLS13/HRR"
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Summarize BoGo JSON results")
    p.add_argument("json_path", nargs="?", help="Path to BoGo JSON output")
    p.add_argument("--self-test", action="store_true", help="Run internal self-test")
    p.add_argument("--max-critical", type=int, default=None, help="Fail if critical_failure_count exceeds this value")
    args = p.parse_args()

    if args.self_test:
        return self_test()

    if not args.json_path:
        print("json_path is required unless --self-test is used", file=sys.stderr)
        return 2

    try:
        out = summarize(args.json_path)
    except Exception as e:
        print(f"failed to summarize: {e}", file=sys.stderr)
        return 1

    print(json.dumps(out, indent=2, sort_keys=True))
    if args.max_critical is not None and out["critical_failure_count"] > args.max_critical:
        print(
            f"critical failure gate exceeded: {out['critical_failure_count']} > {args.max_critical}",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
