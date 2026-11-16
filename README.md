# Agentic Workflow Abuse in GitHub Actions - companion lab files

Companion material for "Detecting Agentic Workflow Abuse in GitHub Actions with Wazuh".

## Contents

- rules/agentic_workflow_rules.xml: nine custom detection rules (110500-110508).
- lab/agent-review.yml: benign demonstration workflow. It does not call a language model.
- tests/scenarios.json: seven synthetic test scenarios, containing 50 events.
- tests/run_tests.py: validates expected rule IDs using wazuh-logtest.
- tests/replay_events.py: sends synthetic events to an isolated Wazuh manager's analysis queue.

## Using the tests

Follow the article to install the custom rules on a test manager. From the cloned repository directory:

```bash
sudo python3 tests/run_tests.py
python3 tests/replay_events.py --list
sudo python3 tests/replay_events.py --scenario 1
```

The replay script generates synthetic alerts. Run it only on an isolated test manager,
not production. Label screenshots of replayed events as synthetic. The included replay
script uses a 0.01-second delay between events; confirm the appropriate delivery rate
for your own test environment. These example scenarios are not a separate automated
reproduction harness for the article's 1,500-chain stress test.

No audit-log token, personal credentials, or operating-system metadata is included.

## About

Written by Albin Haliti as part of the [Wazuh Ambassadors Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
Learn more about [Wazuh](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
