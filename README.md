# email-forwarding-rule-auditor

Audit mailbox forwarding rules from a CSV: EXTERNAL when the forward target's domain is not in --internal-domains, NO TARGET when forward_to is empty, DISABLED when the rule is not enabled, otherwise OK — rules with problems first.

Sample input is included (sample.csv with four forwarding rules).

## How to run

```sh
python3 main.py sample.csv --internal-domains company.local
```

## Example output

```
ali 'To personal' -> ali.personal@gmail.com: EXTERNAL
bob 'To vendor' -> vendor@partner.example: EXTERNAL
omar 'Old rule' -> (none): NO TARGET, DISABLED
sara 'To manager' -> sara.manager@company.local: OK
2 rule(s) forward externally, 1 rule(s) with no target.
```

Standard library only. Run the tests with `python3 -m unittest discover`.
