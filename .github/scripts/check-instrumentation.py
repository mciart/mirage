#!/usr/bin/env python3
"""Check the raw output of `adb shell am instrument -w -r ...`.

Usage: check-instrumentation.py OUTPUT_FILE [--require-passed CLASS]...

Prints one line per test and exits non-zero if
  - any test failed or errored,
  - the instrumentation process crashed or failed to start,
  - the runner's final summary has no "OK (N tests)" line,
  - no test result was reported at all, or
  - a --require-passed class has no passed test (e.g. it was skipped by an
    assumption, which the runner would otherwise report as success).
"""
import argparse
import re
import sys

# Instrumentation status codes (androidx.test InstrumentationResultPrinter).
CODES = {
    0: "PASS",
    -1: "ERROR",
    -2: "FAIL",
    -3: "IGNORED",
    -4: "SKIPPED (assumption failed)",
}


def parse(text):
    """Return a list of (status_code, {key: value}) for each reported status."""
    records = []
    cur = {}
    key = None
    for line in text.splitlines():
        m = re.match(r"INSTRUMENTATION_STATUS: ([^=]+)=(.*)$", line)
        if m:
            key = m.group(1)
            cur[key] = m.group(2)
            continue
        m = re.match(r"INSTRUMENTATION_STATUS_CODE: (-?\d+)", line)
        if m:
            records.append((int(m.group(1)), cur))
            cur, key = {}, None
            continue
        if line.startswith("INSTRUMENTATION_"):
            key = None
            continue
        if key is not None:
            cur[key] += "\n" + line
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output")
    ap.add_argument("--require-passed", action="append", default=[], metavar="CLASS")
    args = ap.parse_args()

    with open(args.output, encoding="utf-8", errors="replace") as f:
        text = f.read()

    problems = []
    results = [(c, r) for c, r in parse(text) if c in CODES]
    passed_classes = set()

    for code, rec in results:
        cls = rec.get("class", "?")
        name = rec.get("test", "?")
        print(f"{CODES[code]:<28} {cls}#{name}")
        if code == 0:
            passed_classes.add(cls)
        elif code in (-1, -2):
            problems.append(f"{cls}#{name} {CODES[code]}")
            stack = rec.get("stack")
            if stack:
                print("    " + stack.strip().replace("\n", "\n    "))

    if not results:
        problems.append("no test results were reported")
    if re.search(r"INSTRUMENTATION_FAILED|Process crashed|INSTRUMENTATION_ABORTED", text):
        problems.append("the instrumentation failed to start or crashed")
    if "FAILURES!!!" in text:
        problems.append("the runner reported FAILURES!!!")
    if not re.search(r"^OK \(\d+ tests?\)", text, re.M):
        problems.append('no "OK (N tests)" line in the output')
    for want in args.require_passed:
        if not any(c == want or c.endswith("." + want) for c in passed_classes):
            problems.append(f"{want} did not pass (missing or skipped; was e2eLink passed?)")

    if problems:
        print("\nInstrumentation check FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"\nInstrumentation check OK ({len(results)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
