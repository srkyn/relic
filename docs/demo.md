# relic Demo

This demo uses sanitized object names and distinguished names. It shows the
kind of evidence relic surfaces for Active Directory hygiene review.

![Sanitized relic terminal output](assets/relic-sample-output.svg)

## What To Notice

- Findings are grouped around stale objects, disabled accounts, passwords, and group memberships.
- `HIGH` means the object deserves review sooner, not that relic proved compromise.
- Disable actions are explicit and should be tested with `--dry-run` first.

## Example Command

```bash
rl --server dc01.corp.local --domain corp.local --only-flagged --output results.json --output-csv results.csv
```

## Example Interpretation

The disabled account with retained group memberships is immediately actionable:
the account is already disabled, so removing group memberships usually reduces
reenablement risk without disrupting active work.
