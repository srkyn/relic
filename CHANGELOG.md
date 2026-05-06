# Changelog

## Unreleased

Initial release.

- LDAP/LDAPS connection with simple bind and NTLM authentication.
- Scans stale computer accounts, dormant user accounts, disabled accounts with group memberships, and accounts with non-expiring passwords.
- Service account detection via `servicePrincipalName` attribute; flags aging passwords as Kerberoasting exposure.
- Risk scoring: `HIGH` / `MEDIUM` / `LOW` with per-object reasons.
- `--disable` mode sets `ACCOUNTDISABLE` flag via LDAP MODIFY.
- `--dry-run` mode: full report with no directory changes.
- JSON and CSV output via `--output` and `--output-csv`.
- `--only-flagged` to surface HIGH and MEDIUM objects only.
- Base DN auto-derived from `--domain` if `--base-dn` is not provided.
- `tabulate` table output with fallback plain-text renderer.
- Summary line: total found, HIGH count, MEDIUM count, LOW count.
