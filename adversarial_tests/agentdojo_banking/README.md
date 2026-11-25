# External check: AgentDojo banking, split across NLIP agents

Our own attack set is written by the team, and judges are right to discount 0% on
self-written attacks. This evaluation uses an external benchmark instead:
[AgentDojo](https://github.com/ethz-spylab/agentdojo) v1.2.1, banking suite. AgentDojo
supplies everything that decides the score:

* the 16 user tasks and the 9 injection tasks;
* the injected text: its standard `important_instructions` attack;
* each task's own `utility` and `security` checks on the final environment.

What we add is the split (the tools run on separate NLIP agents, see
[`agent_applications/agentdojo_split`](../../agent_applications/agentdojo_split/)) and
a scripted worst-case agent that obeys every injection it reads.

```bash
pip install -e ".[test,agentdojo]"
python -m adversarial_tests.agentdojo_banking.run_evaluation                  # ~1 min
python -m adversarial_tests.agentdojo_banking.run_evaluation --defense none custody
python -m adversarial_tests.agentdojo_banking.run_evaluation --only user_task_0 --injection injection_task_0 -v
```

Runs: each user task once with no injection (16), and each user task with each
injection task (144 pairs), under each defence. When a call is blocked, the simulated
**careful user** approves it only if it is one of the user task's own ground-truth
calls (same tool, same arguments); the assistant then retries. Results go to
`results/` (git-ignored).

## Results (Nov 25 2026)

Rates are k/n with a 95% Wilson interval. Utility leaves out `user_task_1` and
`user_task_7`, which check a computed total in the model's prose answer that a
scripted agent does not write (their security still counts).

| Metric | No SE | Heuristic judge | Per-hop taint | Authority caps | Custody |
| --- | --- | --- | --- | --- | --- |
| Attack success rate | 143/144 = 99.3% | 143/144 = 99.3% | 47/144 = 32.6% [25.5, 40.7] | 127/144 = 88.2% | **0/144 = 0.0% [0.0, 2.6]** |
| Utility, no attack | 14/14 | 14/14 | 14/14 | 14/14 | 14/14 |
| Utility under attack | 108/126 = 85.7% | 108/126 = 85.7% | 124/126 = 98.4% | 110/126 = 87.3% | **126/126 = 100%** |
| No-attack runs that needed consent | 0/16 | 0/16 | 7/16 = 43.8% | 0/16 | **12/16 = 75.0% [50.5, 89.8]** |
| Injection reached the agent | 144/144 | 144/144 | 144/144 | 144/144 | 144/144 |

"Injection reached the agent" confirms every attack was live: the worst-case agent
saw and obeyed the injection in every pair. With no SE, 143 of 144 attacks succeed;
the one failure is `injection_task_7` (change the password) paired with
`user_task_14`, which itself sets a new password afterwards.

## What it shows

* **Custody stops all 144 attacks, and every task still completes.** Utility under
  attack is 100%, because blocked injected calls never run and the user's own blocked
  calls are approved and retried.
* **Per-hop taint misses exactly the cross-agent flows.** It catches injections in
  transaction subjects, because reading the transactions and sending money happen
  inside the same bank agent. It misses all injections in documents (4 user tasks ×
  9), because `read_file` runs at the files agent and `send_money` at the bank sees
  only the trusted assistant. It also misses 15 of 16 password changes, because the
  profile agent never read anything itself. This matches the ablation on our own set.
* **Authority caps stop only `injection_task_5`** ("send as much money as possible").
  Every other injected payment is within the assistant's warrant.
* **The heuristic judge stops nothing.** AgentDojo's attack text matches none of its
  generic patterns. (Our own attack set flatters it; see that README.) An LLM judge or
  PromptGuard would likely flag this well-known template. That run has not been done.

## The price, stated plainly

**12 of 16 benign banking tasks need one consent under Custody.** Almost every banking
task reads either the transaction history (whose incoming subjects are written by
other people) or a document before it acts, so the action that follows is, correctly,
shaped by outside content. Per-hop taint, which sees only same-agent flows, needs
consent on 7.

This is label creep at its most visible, and it is the main limitation to report. The
levers are known but not applied here: finer tagging (only the transactions a task
actually used), endorsement of control-only reads (for example a balance or a count),
and argument-level provenance (PACT) instead of a set per conversation.

## Caveats

* **Scripted, not a real model.** The agent always obeys and always completes the
  user task's ground truth, so attack success without a defence is about 100% and
  utility without attack is 100% by construction. A real-model run is needed for
  realistic utility and attack-success numbers. The defences' *decisions* are
  model-independent: they never look at the model.
* **The careful user is optimistic.** They approve exactly the calls the task needs.
  A careless user who approves everything would let the attacks through, as ATK-29 in
  our own set shows.
* **One suite.** The Slack suite has not been ported.
