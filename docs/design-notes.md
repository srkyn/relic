# Design Notes

## The Problem

On-premises Active Directory accumulates objects that nobody is actively managing. Users leave the organization but their accounts persist. Service accounts get created for a project, the project ends, and nobody remembers to disable them. Computer accounts for decommissioned workstations keep sitting in the directory, still appearing in group memberships and policy scope. These aren't exotic edge cases — they're the standard condition of any AD environment that has been running for more than a few years without dedicated hygiene work.

The risk is concrete. A disabled account that still holds membership in privileged groups can be re-enabled by anyone with the right access. A service account with an SPN and a password that hasn't changed in three years is a Kerberoasting target. Computer accounts that haven't authenticated in over a year may belong to machines that were disposed of — or to machines that are still alive but no longer receiving policy updates.

## What relic Checks

**Stale computer accounts** — computers whose `lastLogonTimestamp` attribute predates the threshold. Note that `lastLogonTimestamp` is replicated across domain controllers but imprecise by design (it may lag by up to 14 days by default). Age readings should be interpreted as approximate.

**Dormant user accounts** — users who have not authenticated within the threshold window, identified by `lastLogonTimestamp`. Includes service accounts when `servicePrincipalName` is populated.

**Disabled accounts with group memberships** — accounts with `ACCOUNTDISABLE` set in `userAccountControl` that still appear in `memberOf`. These are the most actionable findings: the account is already disabled, the group memberships are residual, and removing them carries essentially no risk.

**Non-expiring passwords** — enabled accounts with `DONT_EXPIRE_PASSWORD` set in `userAccountControl`. Flagged on its own as MEDIUM; escalates to HIGH when the account is also stale.

## Risk Scoring

| Condition | Severity |
|---|---|
| Disabled account still holds group memberships | HIGH |
| Service account (SPN present), password unchanged >365 days | HIGH — Kerberoasting exposure |
| Computer account, last authentication >365 days ago | HIGH |
| Non-expiring password + inactive >180 days | HIGH |
| Stale account (inactive within threshold) | MEDIUM |
| Non-expiring password, account active | MEDIUM |
| Disabled account, no group memberships | MEDIUM |
| Service account password unchanged >90 days | MEDIUM |
| No flags triggered | LOW |

## Authentication

relic uses `ldap3` with simple bind or NTLM authentication. LDAPS (port 636, `--ssl`) is recommended for production use to avoid transmitting bind credentials in cleartext. Prefer `--password-env` or `--password-stdin` so bind passwords do not remain in shell history or process listings. Kerberos/GSSAPI authentication is not currently supported but is a natural follow-on for environments where tickets are available.

## lastLogonTimestamp vs lastLogon

AD provides two attributes that look similar:

- `lastLogon` — updated on every authentication, but not replicated. Its value depends on which domain controller you query. Not useful for cross-DC queries.
- `lastLogonTimestamp` — replicated across all DCs, but only updated when the timestamp would change by more than roughly 9–14 days (configurable via `ms-DS-LogonTimeSyncInterval`). relic uses `lastLogonTimestamp` for consistency, but results should be interpreted with that lag in mind.

## What relic Does Not Do

- Does not handle Entra ID (cloud identity) — that is lapse's domain.
- Does not evaluate GPO scope or policy inheritance.
- Does not deeply inspect group membership chains (nested groups).
- Does not parse password policy to determine whether a given account's password has actually expired by policy.
- Does not evaluate Kerberos delegation settings.
