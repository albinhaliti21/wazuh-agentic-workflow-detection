#!/usr/bin/env python3
"""Replay the scenarios in scenarios.json through wazuh-logtest and compare rule IDs.

Each scenario runs in its own wazuh-logtest session, so correlation rules
(if_matched_sid / same_field) see the earlier events of that scenario only.

  On the Wazuh manager:   sudo python3 run_tests.py
  Against a container:    python3 run_tests.py --docker <container-name>
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

LOGTEST = "/var/ossec/bin/wazuh-logtest"


def run_session(lines, docker):
    cmd = ["docker", "exec", "-i", docker, LOGTEST] if docker else [LOGTEST]
    proc = subprocess.run(cmd, input="\n".join(lines) + "\n", capture_output=True, text=True)
    return proc.stdout + proc.stderr


def fired_rules(output):
    """One entry per event: (rule id, level) or (None, None) when no rule matched."""
    results = []
    for block in output.split("**Phase 1:")[1:]:
        phase3 = block.split("**Phase 3:")[1] if "**Phase 3:" in block else ""
        rule = re.search(r"\bid: '(\d+)'", phase3)
        level = re.search(r"\blevel: '(\d+)'", phase3)
        results.append((rule.group(1) if rule else None, level.group(1) if level else None))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docker", metavar="CONTAINER", help="run wazuh-logtest inside this container")
    parser.add_argument("--scenarios", default=str(pathlib.Path(__file__).with_name("scenarios.json")))
    args = parser.parse_args()

    scenarios = json.loads(pathlib.Path(args.scenarios).read_text())
    failed = total = 0
    for scenario in scenarios:
        print(f"\n== {scenario['name']}")
        steps = scenario["steps"]
        lines = [json.dumps(step["event"], separators=(",", ":")) for step in steps]
        results = fired_rules(run_session(lines, args.docker))
        if len(results) != len(steps):
            print(f"   ERROR: sent {len(steps)} events, wazuh-logtest reported {len(results)}")
            failed += len(steps)
            total += len(steps)
            continue
        for step, (rule, level) in zip(steps, results):
            total += 1
            expected = step["expect"]
            ok = rule == expected
            failed += not ok
            got = f"rule {rule} (level {level})" if rule else "no rule"
            suffix = "" if ok else f"   <-- expected {expected or 'no rule'}"
            print(f"   {'PASS' if ok else 'FAIL'}  {step['what']:<62} {got}{suffix}")

    print(f"\n{total - failed}/{total} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
