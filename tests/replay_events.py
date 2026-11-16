#!/usr/bin/env python3
"""Replay one scenario from scenarios.json into the live Wazuh analysis engine.

Events are delivered the way the Wazuh GitHub module delivers them: a
'1:github:<json>' datagram on the analysisd queue socket, 10 ms apart
(1 second / wazuh_modules.max_eps). Unlike wazuh-logtest, this produces real
alerts in alerts.json and the dashboard, so it is useful when no GitHub
Enterprise Cloud organization is available. Run it on the Wazuh manager:

  sudo python3 replay_events.py --list
  sudo python3 replay_events.py --scenario 1
"""
import argparse
import json
import pathlib
import socket
import time

QUEUE = "/var/ossec/queue/sockets/queue"
MODULE_DELAY = 0.01


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", default=str(pathlib.Path(__file__).with_name("scenarios.json")))
    parser.add_argument("--scenario", type=int, default=1, help="scenario number, starting at 1")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = parser.parse_args()

    scenarios = json.loads(pathlib.Path(args.scenarios).read_text())
    if args.list:
        for number, scenario in enumerate(scenarios, 1):
            print(f"{number}. {scenario['name']} ({len(scenario['steps'])} events)")
        return

    scenario = scenarios[args.scenario - 1]
    queue = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    queue.connect(QUEUE)
    print(f"Replaying: {scenario['name']}")
    for step in scenario["steps"]:
        time.sleep(MODULE_DELAY)
        queue.send(("1:github:" + json.dumps(step["event"], separators=(",", ":"))).encode())
        print(f"   sent  {step['what']:<62} expect rule {step['expect'] or '-'}")


if __name__ == "__main__":
    main()
