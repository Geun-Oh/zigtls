#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from typing import Any

CRITICAL_PATTERNS = (
    re.compile(r"TLS13", re.IGNORECASE),
    re.compile(r"HRR", re.IGNORECASE),
    re.compile(r"KeyUpdate", re.IGNORECASE),
    re.compile(r"EarlyData", re.IGNORECASE),
    re.compile(r"Resumption", re.IGNORECASE),
)

CATEGORY_PATTERNS = (
    ("hrr", re.compile(r"HRR|HelloRetryRequest", re.IGNORECASE)),
    ("keyupdate", re.compile(r"KeyUpdate", re.IGNORECASE)),
    ("early_data", re.compile(r"EarlyData|0-RTT", re.IGNORECASE)),
    ("resumption", re.compile(r"Resumption|SessionTicket|PSK", re.IGNORECASE)),
    ("certificate", re.compile(r"Certificate|OCSP|X509", re.IGNORECASE)),
    ("record", re.compile(r"Record", re.IGNORECASE)),
    ("alert", re.compile(r"Alert|close_notify", re.IGNORECASE)),
    ("tls13", re.compile(r"TLS13", re.IGNORECASE)),
    ("basic", re.compile(r"Basic", re.IGNORECASE)),
)

NON_PASS_STATUSES = {"fail", "crash", "timeout", "skip", "unknown"}


def is_critical_test(name: str) -> bool:
    return any(p.search(name) for p in CRITICAL_PATTERNS)


def classify_test_category(name: str) -> str:
    for category, pattern in CATEGORY_PATTERNS:
        if pattern.search(name):
            return category
    return "misc"


def load_results(path: str) -> list[tuple[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    tests = data.get("tests", []) if isinstance(data, dict) else []
    iterable: list[tuple[str, str]] = []
    if isinstance(tests, list):
        for t in tests:
            if not isinstance(t, dict):
                continue
            iterable.append((str(t.get("name", "unknown")), str(t.get("result", "unknown"))))
    elif isinstance(tests, dict):
        for name, meta in tests.items():
            if isinstance(meta, dict):
                iterable.append((str(name), str(meta.get("actual", "unknown"))))
            else:
                iterable.append((str(name), "unknown"))
    return iterable


def compile_profile(profile_path: str) -> dict[str, Any]:
    with open(profile_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    classes = raw.get("classes", {})
    class_order = raw.get("class_order", list(classes.keys()))
    default_class = raw.get("default_class", "out_of_scope")

    compiled: dict[str, list[re.Pattern[str]]] = {}
    for klass, patterns in classes.items():
        compiled[klass] = [re.compile(p, re.IGNORECASE) for p in patterns]

    return {
        "name": raw.get("name", "unnamed"),
        "version": raw.get("version", 1),
        "default_class": default_class,
        "class_order": class_order,
        "compiled": compiled,
    }


def classify_with_profile(name: str, profile: dict[str, Any]) -> str:
    compiled = profile["compiled"]
    for klass in profile["class_order"]:
        patterns = compiled.get(klass, [])
        for pat in patterns:
            if pat.search(name):
                return klass
    return profile["default_class"]


def summarize(path: str, profile_path: str | None = None) -> dict:
    rows = load_results(path)

    status_counter = Counter()
    suite_counter = defaultdict(Counter)
    category_counter = defaultdict(Counter)
    critical_failures: list[str] = []

    profile = compile_profile(profile_path) if profile_path else None
    class_counter = defaultdict(Counter)

    for name, raw_status in rows:
        status = str(raw_status).lower()
        suite = name.split("/")[0] if "/" in name else "misc"
        category = classify_test_category(name)
        status_counter[status] += 1
        suite_counter[suite][status] += 1
        category_counter[category][status] += 1

        if profile is not None:
            klass = classify_with_profile(name, profile)
            class_counter[klass][status] += 1

        if status in ("fail", "crash", "timeout") and is_critical_test(name):
            critical_failures.append(name)

    in_scope_required_status = dict(class_counter.get("in_scope_required", {}))
    in_scope_required_total = sum(in_scope_required_status.values())
    in_scope_required_non_pass = sum(
        count for st, count in in_scope_required_status.items() if st in NON_PASS_STATUSES
    )

    out = {
        "total": sum(status_counter.values()),
        "status": dict(status_counter),
        "suites": {k: dict(v) for k, v in sorted(suite_counter.items())},
        "categories": {k: dict(v) for k, v in sorted(category_counter.items())},
        "critical_failures": sorted(critical_failures),
        "critical_failure_count": len(critical_failures),
    }

    if profile is not None:
        out["profile"] = {
            "name": profile["name"],
            "version": profile["version"],
            "default_class": profile["default_class"],
        }
        out["classification"] = {k: dict(v) for k, v in sorted(class_counter.items())}
        out["in_scope_required_total"] = in_scope_required_total
        out["in_scope_required_non_pass"] = in_scope_required_non_pass
        out["out_of_scope_total"] = sum(class_counter.get("out_of_scope", {}).values())

    return out


def evaluate_critical_gate(summary: dict, max_critical: int | None) -> int:
    if max_critical is None:
        return 0
    if summary["critical_failure_count"] > max_critical:
        return 3
    return 0


def evaluate_strict_gate(summary: dict, strict: bool) -> int:
    if not strict:
        return 0

    if "in_scope_required_total" not in summary:
        return 6

    if summary["in_scope_required_total"] == 0:
        return 5

    if summary["in_scope_required_non_pass"] > 0:
        return 4

    return 0


def self_test() -> int:
    sample = {
        "tests": [
            {"name": "TLS13/BasicHandshake", "result": "PASS"},
            {"name": "TLS13/HRR", "result": "FAIL"},
            {"name": "Record/Overflow", "result": "PASS"},
            {"name": "NoDelimiterCase", "result": "PASS"},
        ]
    }
    path = "/tmp/zigtls-bogo-selftest.json"
    profile_path = "/tmp/zigtls-bogo-selftest-profile.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sample, f)

    profile = {
        "name": "selftest",
        "version": 1,
        "class_order": ["out_of_scope", "in_scope_required", "in_scope_optional"],
        "classes": {
            "out_of_scope": ["Record"],
            "in_scope_required": ["TLS13|HRR"],
            "in_scope_optional": ["NoDelimiter"],
        },
        "default_class": "out_of_scope",
    }
    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(profile, f)

    out = summarize(path, profile_path)
    assert out["total"] == 4
    assert out["status"].get("pass") == 3
    assert out["status"].get("fail") == 1
    assert out["critical_failure_count"] == 1
    assert out["in_scope_required_total"] == 2
    assert out["in_scope_required_non_pass"] == 1
    assert out["out_of_scope_total"] == 1
    assert evaluate_critical_gate(out, 0) == 3
    assert evaluate_critical_gate(out, 1) == 0
    assert evaluate_strict_gate(out, True) == 4

    sample_v3 = {
        "tests": {
            "TLS13/BasicHandshake": {"actual": "PASS"},
            "TLS13/KeyUpdate": {"actual": "PASS"},
            "NoDelimiterCase": {"actual": "SKIP"},
        }
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sample_v3, f)

    out_v3 = summarize(path, profile_path)
    assert out_v3["total"] == 3
    assert out_v3["in_scope_required_total"] == 2
    assert out_v3["in_scope_required_non_pass"] == 0
    assert evaluate_strict_gate(out_v3, True) == 0

    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Summarize BoGo JSON results")
    p.add_argument("json_path", nargs="?", help="Path to BoGo JSON output")
    p.add_argument("--self-test", action="store_true", help="Run internal self-test")
    p.add_argument("--max-critical", type=int, default=None, help="Fail if critical_failure_count exceeds this value")
    p.add_argument("--profile", default=None, help="Profile json path for in/out-of-scope classification")
    p.add_argument("--strict", action="store_true", help="Enforce strict in_scope_required gate")
    args = p.parse_args()

    if args.self_test:
        return self_test()

    if not args.json_path:
        print("json_path is required unless --self-test is used", file=sys.stderr)
        return 2

    try:
        out = summarize(args.json_path, args.profile)
    except Exception as e:
        print(f"failed to summarize: {e}", file=sys.stderr)
        return 1

    print(json.dumps(out, indent=2, sort_keys=True))

    gate_code = evaluate_critical_gate(out, args.max_critical)
    if gate_code != 0:
        print(
            f"critical failure gate exceeded: {out['critical_failure_count']} > {args.max_critical}",
            file=sys.stderr,
        )
        return gate_code

    strict_code = evaluate_strict_gate(out, args.strict)
    if strict_code == 6:
        print("strict mode requires profile classification output", file=sys.stderr)
        return strict_code
    if strict_code == 5:
        print("strict gate failed: in_scope_required_total is zero", file=sys.stderr)
        return strict_code
    if strict_code == 4:
        print(
            f"strict gate failed: in_scope_required_non_pass={out['in_scope_required_non_pass']}",
            file=sys.stderr,
        )
        return strict_code

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
