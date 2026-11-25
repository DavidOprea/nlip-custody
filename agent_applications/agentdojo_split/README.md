# AgentDojo banking, split across NLIP agents

[AgentDojo](https://github.com/ethz-spylab/agentdojo)'s banking suite (v1.2.1)
rebuilt as a multi-agent NLIP system. Each AgentDojo tool runs on the agent that
would own it:

| Agent | Custody identity | Org | AgentDojo tools |
| --- | --- | --- | --- |
| user client | `agent:acme/user-client` | acme | none (the human) |
| assistant | `agent:acme/assistant` | acme | none: runs the task by calling the others over NLIP |
| files | `agent:acme/files` | acme | `read_file` (bills and notices: outside content) |
| bank | `agent:bank/bank` | bank | `get_iban`, `send_money`, `schedule_transaction`, `update_scheduled_transaction`, `get_balance`, `get_most_recent_transactions`, `get_scheduled_transactions` |
| profile | `agent:bank/profile` | bank | `get_user_info`, `update_password`, `update_user_info` |

Tasks, injected text and scoring are AgentDojo's own. [`config.toml`](config.toml)
holds the defences, loaded through the same settings code as the custody demo:

* **Sources of outside content:** documents from the file store, and the subjects of
  incoming transactions, which are written by whoever sent the money. The user's own
  transactions ("me") are not outside content.
* **Sensitive tools:** sending, scheduling and updating money, and changing the
  password or profile. The allowed principals are the user and the participating
  agents, not outside content.

The assistant is the scripted worst case. It runs the user task's AgentDojo ground
truth, and the moment a tool output contains the injected text, it runs the injection
task's ground truth too. It runs in-process only, because the AgentDojo environment is
one shared Python object.

Install and run (the evaluation is in
[`adversarial_tests/agentdojo_banking`](../../adversarial_tests/agentdojo_banking/)):

```bash
pip install -e ".[test,agentdojo]"
python -m adversarial_tests.agentdojo_banking.run_evaluation
```
