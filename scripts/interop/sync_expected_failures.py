#!/usr/bin/env python3
import argparse
import json
import os
import tempfile
from typing import Any

import bogo_summary


def collect_in_scope_required_non_pass(results_path: str, profile_path: str) -> list[str]:
    profile = bogo_summary.compile_profile(profile_path)
    rows = bogo_summary.load_results(results_path)
    out: set[str] = set()
    for name, raw_status in rows:
        status = str(raw_status).lower()
        klass = bogo_summary.classify_with_profile(name, profile)
        if klass != "in_scope_required":
            continue
        if status not in bogo_summary.NON_PASS_STATUSES:
            continue
        out.add(name)
    return sorted(out)


def write_inventory(path: str, names: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for name in names:
            f.write(f"{name}\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="zigtls-sync-ef-") as td:
        results_path = os.path.join(td, "results.json")
        profile_path = os.path.join(td, "profile.json")
        output_path = os.path.join(td, "expected.txt")

        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "tests": [
                        {"name": "TLS13/BasicHandshake", "result": "PASS"},
                        {"name": "TLS13/HRR", "result": "SKIP"},
                        {"name": "Record/Overflow", "result": "FAIL"},
                    ]
                },
                f,
            )

        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "name": "selftest",
                    "version": 1,
                    "class_order": ["out_of_scope", "in_scope_required", "in_scope_optional"],
                    "classes": {
                        "out_of_scope": ["Record"],
                        "in_scope_required": ["TLS13|HRR"],
                        "in_scope_optional": [],
                    },
                    "default_class": "out_of_scope",
                },
                f,
            )

        names = collect_in_scope_required_non_pass(results_path, profile_path)
        assert names == ["TLS13/HRR"]
        write_inventory(output_path, names)
        with open(output_path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        assert lines == ["TLS13/HRR"]
        return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Sync explicit expected-failure inventory from BoGo JSON results")
    p.add_argument("--self-test", action="store_true", help="Run internal self-test")
    p.add_argument("--json", dest="json_path", default=None, help="BoGo JSON results path")
    p.add_argument("--profile", dest="profile_path", default=None, help="BoGo profile path")
    p.add_argument("--out", dest="output_path", default=None, help="expected-failure inventory output path")
    args = p.parse_args()

    if args.self_test:
        return self_test()

    if not args.json_path or not args.profile_path or not args.output_path:
        p.error("--json, --profile, and --out are required unless --self-test is used")

    names = collect_in_scope_required_non_pass(args.json_path, args.profile_path)
    write_inventory(args.output_path, names)
    print(f"wrote {len(names)} expected failures to {args.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
