"""relic.py — Surface stale and orphaned objects in on-premises Active Directory.

Connects to an AD domain controller over LDAP and reports on objects that have
outlasted their purpose: stale computer accounts, dormant users, disabled accounts
still holding group memberships, service accounts with aging passwords, and accounts
configured to never expire.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import ldap3
    from ldap3 import ALL_ATTRIBUTES, SUBTREE, Connection, Server
    _HAS_LDAP3 = True
except ImportError:
    _HAS_LDAP3 = False

try:
    from tabulate import tabulate
    _HAS_TABULATE = True
except ImportError:
    _HAS_TABULATE = False

VERSION = "0.1.0"
DEFAULT_DAYS = 90
DEFAULT_PORT = 389
LDAPS_PORT = 636

# Windows FILETIME: 100-nanosecond intervals since 1601-01-01.
# Offset between 1601-01-01 and 1970-01-01 in 100ns units.
_AD_EPOCH = 116444736000000000

# userAccountControl bitmask flags.
_UAC_DISABLED = 0x0002
_UAC_DONT_EXPIRE_PASSWORD = 0x10000
_UAC_WORKSTATION_TRUST = 0x1000
_UAC_SERVER_TRUST = 0x2000

# LDAP matching rule OID for bitwise AND (used to filter on UAC flags).
_LDAP_BIT_AND = "1.2.840.113556.1.4.803"

# Attributes to retrieve for all objects.
_USER_ATTRS = [
    "sAMAccountName", "distinguishedName", "cn", "description",
    "lastLogonTimestamp", "pwdLastSet", "userAccountControl",
    "memberOf", "whenCreated", "servicePrincipalName", "mail",
    "objectClass", "accountExpires",
]
_COMPUTER_ATTRS = [
    "sAMAccountName", "distinguishedName", "cn", "description",
    "lastLogonTimestamp", "pwdLastSet", "userAccountControl",
    "memberOf", "whenCreated", "operatingSystem", "operatingSystemVersion",
    "objectClass", "dNSHostName",
]


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _filetime_to_dt(filetime: Any) -> Optional[datetime]:
    """Convert an AD FILETIME integer to a UTC datetime."""
    try:
        v = int(filetime)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    # Some AD implementations signal "never" as the max int64 value.
    if v >= 9223372036854775807:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)
    except (OverflowError, OSError):
        return None


def _dt_to_filetime(dt: datetime) -> int:
    """Convert a UTC datetime to an AD FILETIME integer."""
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int(delta.total_seconds() * 10_000_000)


def _age(dt: Optional[datetime], now: datetime) -> Optional[int]:
    """Return days since dt, or None if dt is unavailable."""
    if dt is None:
        return None
    return max(0, (now - dt).days)


def _uac(entry: Dict, flag: int) -> bool:
    """Return True if a UAC flag is set on the entry."""
    try:
        return bool(int(entry.get("userAccountControl", 0)) & flag)
    except (TypeError, ValueError):
        return False


def _fmt_date(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d") if dt else "—"


# ---------------------------------------------------------------------------
# LDAP connection
# ---------------------------------------------------------------------------

def derive_base_dn(domain: str) -> str:
    """Convert a domain name to a base DN.

    Example: corp.example.com -> DC=corp,DC=example,DC=com
    """
    return ",".join(f"DC={part}" for part in domain.split("."))


def build_connection(args: argparse.Namespace) -> "Connection":
    """Build and bind an ldap3 Connection from CLI arguments."""
    if not _HAS_LDAP3:
        _die("ldap3 is not installed. Run: pip install ldap3")

    use_ssl = args.ssl or args.port == LDAPS_PORT
    server = Server(args.server, port=args.port, use_ssl=use_ssl, get_info=ldap3.ALL)

    user = args.username
    # If username doesn't contain @ or \, prepend domain for NTLM-style auth.
    if user and "@" not in user and "\\" not in user and args.domain:
        user = f"{args.domain}\\{user}"

    conn = Connection(
        server,
        user=user,
        password=args.password,
        authentication=ldap3.NTLM if (args.domain and "\\" in (user or "")) else ldap3.SIMPLE,
        auto_bind=True,
    )
    return conn


# ---------------------------------------------------------------------------
# LDAP search helpers
# ---------------------------------------------------------------------------

def _search(
    conn: "Connection",
    base_dn: str,
    ldap_filter: str,
    attributes: List[str],
) -> List[Dict]:
    """Run a subtree search and return a list of plain attribute dicts."""
    conn.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        search_scope=SUBTREE,
        attributes=attributes,
    )
    results = []
    for entry in conn.entries:
        obj: Dict[str, Any] = {"_dn": entry.entry_dn}
        for attr in attributes:
            try:
                val = entry[attr].value
            except ldap3.core.exceptions.LDAPKeyError:
                val = None
            obj[attr] = val
        results.append(obj)
    return results


def _is_computer(obj: Dict) -> bool:
    oc = obj.get("objectClass") or []
    if isinstance(oc, str):
        oc = [oc]
    return "computer" in [c.lower() for c in oc]


# ---------------------------------------------------------------------------
# Scan functions
# ---------------------------------------------------------------------------

def scan_stale_computers(
    conn: "Connection",
    base_dn: str,
    cutoff: datetime,
    now: datetime,
) -> List[Dict]:
    """Find computer accounts that have not authenticated since cutoff."""
    filetime = _dt_to_filetime(cutoff)
    ldap_filter = (
        f"(&(objectClass=computer)"
        f"(lastLogonTimestamp<={filetime}))"
    )
    raw = _search(conn, base_dn, ldap_filter, _COMPUTER_ATTRS)
    results = []
    for obj in raw:
        last_dt = _filetime_to_dt(obj.get("lastLogonTimestamp"))
        pwd_dt = _filetime_to_dt(obj.get("pwdLastSet"))
        disabled = _uac(obj, _UAC_DISABLED)
        results.append({
            "type": "computer",
            "name": obj.get("sAMAccountName") or obj.get("cn") or "",
            "dn": obj.get("_dn", ""),
            "os": obj.get("operatingSystem") or "",
            "last_logon": last_dt,
            "last_logon_str": _fmt_date(last_dt),
            "age_days": _age(last_dt, now),
            "pwd_last_set": pwd_dt,
            "disabled": disabled,
            "member_of": _normalise_groups(obj.get("memberOf")),
            "when_created": obj.get("whenCreated"),
            "description": obj.get("description") or "",
            "dns_host": obj.get("dNSHostName") or "",
        })
    return results


def scan_stale_users(
    conn: "Connection",
    base_dn: str,
    cutoff: datetime,
    now: datetime,
) -> List[Dict]:
    """Find user accounts that have not logged in since cutoff."""
    filetime = _dt_to_filetime(cutoff)
    ldap_filter = (
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(lastLogonTimestamp<={filetime}))"
    )
    raw = _search(conn, base_dn, ldap_filter, _USER_ATTRS)
    results = []
    for obj in raw:
        last_dt = _filetime_to_dt(obj.get("lastLogonTimestamp"))
        pwd_dt = _filetime_to_dt(obj.get("pwdLastSet"))
        disabled = _uac(obj, _UAC_DISABLED)
        never_expires = _uac(obj, _UAC_DONT_EXPIRE_PASSWORD)
        spns = obj.get("servicePrincipalName") or []
        is_service = bool(spns) if not isinstance(spns, str) else bool(spns)
        results.append({
            "type": "service_account" if is_service else "user",
            "name": obj.get("sAMAccountName") or obj.get("cn") or "",
            "dn": obj.get("_dn", ""),
            "last_logon": last_dt,
            "last_logon_str": _fmt_date(last_dt),
            "age_days": _age(last_dt, now),
            "pwd_last_set": pwd_dt,
            "pwd_age_days": _age(pwd_dt, now),
            "disabled": disabled,
            "never_expires": never_expires,
            "member_of": _normalise_groups(obj.get("memberOf")),
            "spns": spns if isinstance(spns, list) else ([spns] if spns else []),
            "when_created": obj.get("whenCreated"),
            "description": obj.get("description") or "",
        })
    return results


def scan_disabled_with_memberships(
    conn: "Connection",
    base_dn: str,
    now: datetime,
) -> List[Dict]:
    """Find disabled accounts that still hold group memberships."""
    ldap_filter = (
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:{_LDAP_BIT_AND}:={_UAC_DISABLED})"
        f"(memberOf=*))"
    )
    raw = _search(conn, base_dn, ldap_filter, _USER_ATTRS)
    results = []
    for obj in raw:
        last_dt = _filetime_to_dt(obj.get("lastLogonTimestamp"))
        pwd_dt = _filetime_to_dt(obj.get("pwdLastSet"))
        groups = _normalise_groups(obj.get("memberOf"))
        spns = obj.get("servicePrincipalName") or []
        results.append({
            "type": "service_account" if spns else "user",
            "name": obj.get("sAMAccountName") or obj.get("cn") or "",
            "dn": obj.get("_dn", ""),
            "last_logon": last_dt,
            "last_logon_str": _fmt_date(last_dt),
            "age_days": _age(last_dt, now),
            "pwd_last_set": pwd_dt,
            "pwd_age_days": _age(pwd_dt, now),
            "disabled": True,
            "never_expires": _uac(obj, _UAC_DONT_EXPIRE_PASSWORD),
            "member_of": groups,
            "group_count": len(groups),
            "spns": spns if isinstance(spns, list) else ([spns] if spns else []),
            "when_created": obj.get("whenCreated"),
            "description": obj.get("description") or "",
        })
    return results


def scan_never_expires(
    conn: "Connection",
    base_dn: str,
    now: datetime,
    days: int,
) -> List[Dict]:
    """Find enabled accounts configured with non-expiring passwords."""
    ldap_filter = (
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(!(userAccountControl:{_LDAP_BIT_AND}:={_UAC_DISABLED}))"
        f"(userAccountControl:{_LDAP_BIT_AND}:={_UAC_DONT_EXPIRE_PASSWORD}))"
    )
    raw = _search(conn, base_dn, ldap_filter, _USER_ATTRS)
    results = []
    for obj in raw:
        last_dt = _filetime_to_dt(obj.get("lastLogonTimestamp"))
        pwd_dt = _filetime_to_dt(obj.get("pwdLastSet"))
        spns = obj.get("servicePrincipalName") or []
        results.append({
            "type": "service_account" if spns else "user",
            "name": obj.get("sAMAccountName") or obj.get("cn") or "",
            "dn": obj.get("_dn", ""),
            "last_logon": last_dt,
            "last_logon_str": _fmt_date(last_dt),
            "age_days": _age(last_dt, now),
            "pwd_last_set": pwd_dt,
            "pwd_age_days": _age(pwd_dt, now),
            "disabled": False,
            "never_expires": True,
            "member_of": _normalise_groups(obj.get("memberOf")),
            "spns": spns if isinstance(spns, list) else ([spns] if spns else []),
            "when_created": obj.get("whenCreated"),
            "description": obj.get("description") or "",
        })
    return results


def _normalise_groups(raw: Any) -> List[str]:
    """Return a list of group CNs from a memberOf value."""
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    groups = []
    for dn in raw:
        # Extract the CN from the full DN string.
        parts = str(dn).split(",")
        if parts:
            cn = parts[0].replace("CN=", "").replace("cn=", "").strip()
            groups.append(cn)
    return groups


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def score_object(obj: Dict) -> Tuple[str, List[str]]:
    """Return (risk_level, [reasons]) for a directory object."""
    reasons: List[str] = []
    age = obj.get("age_days")
    pwd_age = obj.get("pwd_age_days")
    disabled = obj.get("disabled", False)
    never_expires = obj.get("never_expires", False)
    groups = obj.get("member_of", [])
    spns = obj.get("spns", [])
    obj_type = obj.get("type", "")

    high = False

    # HIGH conditions
    if disabled and groups:
        reasons.append(f"disabled account holds {len(groups)} group membership(s)")
        high = True
    if spns and pwd_age is not None and pwd_age > 365:
        reasons.append(f"service account (SPN) password unchanged for {pwd_age} days — Kerberoasting exposure")
        high = True
    if obj_type == "computer" and age is not None and age > 365:
        reasons.append(f"computer account inactive for {age} days")
        high = True
    if never_expires and age is not None and age > 180:
        reasons.append(f"non-expiring password, inactive {age} days")
        high = True

    if high:
        return "HIGH", reasons

    # MEDIUM conditions
    if age is not None and age > 0:
        reasons.append(f"inactive for {age} days")
    if never_expires:
        reasons.append("password set to never expire")
    if disabled and not groups:
        reasons.append("account disabled")
    if spns and pwd_age is not None and pwd_age > 90:
        reasons.append(f"service account password unchanged for {pwd_age} days")

    if reasons:
        return "MEDIUM", reasons

    return "LOW", ["no flags"]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(objects: List[Dict]) -> List[Dict]:
    """Remove duplicate entries by DN, keeping the highest-risk copy."""
    rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    seen: Dict[str, Dict] = {}
    for obj in objects:
        dn = obj.get("dn", "")
        risk, reasons = score_object(obj)
        obj["risk"] = risk
        obj["risk_reasons"] = reasons
        if dn not in seen or rank[risk] > rank[seen[dn]["risk"]]:
            seen[dn] = obj
    return list(seen.values())


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_table(objects: List[Dict]) -> None:
    """Print a human-readable table of flagged objects sorted by risk then age."""
    if not objects:
        print("No objects found matching the scan criteria.")
        return

    rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    sorted_objs = sorted(
        objects,
        key=lambda o: (rank.get(o.get("risk", "LOW"), 0), o.get("age_days") or 0),
        reverse=True,
    )

    rows = []
    for obj in sorted_objs:
        name = (obj.get("name") or "")[:28]
        obj_type = (obj.get("type") or "")[:14]
        last = obj.get("last_logon_str", "—")
        age = obj.get("age_days", "—")
        risk = obj.get("risk", "LOW")
        reason = "; ".join(obj.get("risk_reasons", []))[:55]
        rows.append([name, obj_type, last, age, risk, reason])

    headers = ["Name", "Type", "Last Logon", "Days", "Risk", "Reason"]
    if _HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="simple"))
    else:
        widths = [max(len(str(r[i])) for r in ([headers] + rows)) for i in range(len(headers))]
        print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
        print("  ".join("-" * w for w in widths))
        for row in rows:
            print("  ".join(str(v).ljust(widths[i]) for i, v in enumerate(row)))


def write_json(objects: List[Dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(objects, fh, indent=2, default=str)
    print(f"  JSON written to {path}")


def write_csv(objects: List[Dict], path: str) -> None:
    if not objects:
        return
    fields = [
        "name", "type", "dn", "last_logon_str", "age_days",
        "pwd_age_days", "disabled", "never_expires", "group_count",
        "risk", "risk_reasons", "os", "description",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for obj in objects:
            row = dict(obj)
            row["group_count"] = len(obj.get("member_of", []))
            row["risk_reasons"] = "; ".join(obj.get("risk_reasons", []))
            writer.writerow(row)
    print(f"  CSV written to {path}")


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def disable_object(conn: "Connection", dn: str, dry_run: bool) -> bool:
    """Set userAccountControl ACCOUNTDISABLE on an object. Returns True on success."""
    if dry_run:
        return True
    try:
        conn.search(dn, "(objectClass=*)", attributes=["userAccountControl"])
        if not conn.entries:
            return False
        current = int(conn.entries[0]["userAccountControl"].value)
        new_val = current | _UAC_DISABLED
        conn.modify(dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [new_val])]})
        return conn.result["result"] == 0
    except Exception:
        return False


def apply_action(
    conn: "Connection",
    objects: List[Dict],
    args: argparse.Namespace,
) -> None:
    """Apply --disable to flagged objects."""
    if not objects or not args.disable:
        return
    if args.dry_run:
        print(f"  Dry run: would disable {len(objects)} object(s). No changes made.")
        return

    ok = fail = 0
    for obj in objects:
        dn = obj.get("dn", "")
        name = obj.get("name", dn)
        if disable_object(conn, dn, dry_run=False):
            ok += 1
            print(f"  Disabled: {name}")
        else:
            fail += 1
            print(f"  FAILED: {name}", file=sys.stderr)
    print(f"\n  Disable complete — {ok} succeeded, {fail} failed.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="relic",
        description=(
            "Surface stale and orphaned objects in on-premises Active Directory.\n"
            "Finds computer accounts that have stopped authenticating, dormant user\n"
            "accounts, disabled accounts still holding group memberships, service\n"
            "accounts with aging passwords, and accounts set to never expire."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"relic {VERSION}")

    conn_group = parser.add_argument_group("connection")
    conn_group.add_argument("--server", required=True, metavar="HOST",
                            help="Domain controller hostname or IP address.")
    conn_group.add_argument("--domain", metavar="DOMAIN",
                            help="Domain name (e.g. corp.example.com). Used to derive base DN if --base-dn is not set.")
    conn_group.add_argument("--username", metavar="USER",
                            help="Bind username. Prefix with DOMAIN\\ for NTLM.")
    conn_group.add_argument("--password", metavar="PASS",
                            help="Bind password.")
    conn_group.add_argument("--base-dn", metavar="DN",
                            help="Base DN for searches. Derived from --domain if not specified.")
    conn_group.add_argument("--port", type=int, default=DEFAULT_PORT, metavar="N",
                            help=f"LDAP port (default: {DEFAULT_PORT}).")
    conn_group.add_argument("--ssl", action="store_true",
                            help="Use LDAPS (TLS). Implied if --port 636.")

    scan_group = parser.add_argument_group("scan targets")
    scan_group.add_argument("--users", action="store_true",
                            help="Scan for stale user accounts.")
    scan_group.add_argument("--computers", action="store_true",
                            help="Scan for stale computer accounts.")
    scan_group.add_argument("--disabled", action="store_true",
                            help="Find disabled accounts with group memberships.")
    scan_group.add_argument("--never-expires", action="store_true",
                            help="Find enabled accounts with non-expiring passwords.")
    scan_group.add_argument("--days", type=int, default=DEFAULT_DAYS, metavar="N",
                            help=f"Inactivity threshold in days (default: {DEFAULT_DAYS}).")

    output_group = parser.add_argument_group("output")
    output_group.add_argument("--output", metavar="FILE", help="Write JSON report to FILE.")
    output_group.add_argument("--output-csv", metavar="FILE", help="Write CSV report to FILE.")
    output_group.add_argument("--only-flagged", action="store_true",
                              help="Show MEDIUM and HIGH risk objects only.")
    output_group.add_argument("--quiet", action="store_true",
                              help="Suppress table; print summary only.")

    action_group = parser.add_argument_group("actions")
    action_group.add_argument("--disable", action="store_true",
                              help="Disable flagged objects (sets ACCOUNTDISABLE flag).")
    action_group.add_argument("--dry-run", action="store_true",
                              help="Report without making any changes.")

    return parser.parse_args(argv)


def _die(message: str) -> None:
    print(f"relic: error: {message}", file=sys.stderr)
    sys.exit(1)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if not _HAS_LDAP3:
        _die("ldap3 is not installed. Run: pip install ldap3 tabulate")

    # Derive base DN from domain if not explicitly provided.
    base_dn = args.base_dn
    if not base_dn:
        if not args.domain:
            _die("Provide --base-dn or --domain to derive the search base.")
        base_dn = derive_base_dn(args.domain)

    # If no specific scan targets are requested, run all.
    run_all = not any([args.users, args.computers, args.disabled, args.never_expires])

    now = _utc_now()
    cutoff = now - timedelta(days=args.days)

    print(f"Connecting to {args.server}:{args.port}...")
    try:
        conn = build_connection(args)
    except Exception as exc:
        _die(f"LDAP connection failed: {exc}")

    print(f"Connected. Base DN: {base_dn}")
    print(f"Threshold: {args.days} days (cutoff: {cutoff.date()})\n")

    all_objects: List[Dict] = []

    if run_all or args.computers:
        print("Scanning computer accounts...", end=" ", flush=True)
        computers = scan_stale_computers(conn, base_dn, cutoff, now)
        print(f"{len(computers)} found.")
        all_objects.extend(computers)

    if run_all or args.users:
        print("Scanning user accounts...", end=" ", flush=True)
        users = scan_stale_users(conn, base_dn, cutoff, now)
        print(f"{len(users)} found.")
        all_objects.extend(users)

    if run_all or args.disabled:
        print("Scanning disabled accounts with memberships...", end=" ", flush=True)
        disabled = scan_disabled_with_memberships(conn, base_dn, now)
        print(f"{len(disabled)} found.")
        all_objects.extend(disabled)

    if run_all or args.never_expires:
        print("Scanning accounts with non-expiring passwords...", end=" ", flush=True)
        never = scan_never_expires(conn, base_dn, now, args.days)
        print(f"{len(never)} found.")
        all_objects.extend(never)

    # Score and deduplicate.
    all_objects = deduplicate(all_objects)

    if args.only_flagged:
        all_objects = [o for o in all_objects if o.get("risk") in ("HIGH", "MEDIUM")]

    high = sum(1 for o in all_objects if o.get("risk") == "HIGH")
    medium = sum(1 for o in all_objects if o.get("risk") == "MEDIUM")

    if not args.quiet:
        print()
        print_table(all_objects)
        print()

    if args.output:
        write_json(all_objects, args.output)
    if args.output_csv:
        write_csv(all_objects, args.output_csv)

    if args.disable:
        flagged = [o for o in all_objects if o.get("risk") in ("HIGH", "MEDIUM")]
        apply_action(conn, flagged, args)

    print(
        f"Found {len(all_objects)} object(s) — "
        f"{high} HIGH, {medium} MEDIUM, "
        f"{len(all_objects) - high - medium} LOW."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
