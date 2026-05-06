"""Unit tests for relic.py."""

import csv
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import relic


def _now():
    return datetime.now(timezone.utc)


def _filetime(days_ago: int) -> int:
    dt = _now() - timedelta(days=days_ago)
    return relic._dt_to_filetime(dt)


def _obj(
    name="TESTUSER",
    obj_type="user",
    days_ago=100,
    disabled=False,
    never_expires=False,
    groups=None,
    spns=None,
    pwd_days_ago=None,
):
    return {
        "name": name,
        "type": obj_type,
        "dn": f"CN={name},DC=test,DC=local",
        "last_logon": _now() - timedelta(days=days_ago),
        "last_logon_str": (_now() - timedelta(days=days_ago)).strftime("%Y-%m-%d"),
        "age_days": days_ago,
        "pwd_last_set": (_now() - timedelta(days=pwd_days_ago)) if pwd_days_ago else None,
        "pwd_age_days": pwd_days_ago,
        "disabled": disabled,
        "never_expires": never_expires,
        "member_of": groups or [],
        "group_count": len(groups or []),
        "spns": spns or [],
        "description": "",
        "os": "",
    }


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class VersionTests(unittest.TestCase):
    def test_version_string(self):
        self.assertRegex(relic.VERSION, r"^\d+\.\d+\.\d+$")

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            relic.parse_args(["--version", "--server", "dc.local"])
        self.assertEqual(ctx.exception.code, 0)


# ---------------------------------------------------------------------------
# FILETIME conversion
# ---------------------------------------------------------------------------

class FiletimeTests(unittest.TestCase):
    def test_roundtrip(self):
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ft = relic._dt_to_filetime(now)
        restored = relic._filetime_to_dt(ft)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.year, 2025)
        self.assertEqual(restored.month, 6)

    def test_zero_returns_none(self):
        self.assertIsNone(relic._filetime_to_dt(0))

    def test_negative_returns_none(self):
        self.assertIsNone(relic._filetime_to_dt(-1))

    def test_max_int64_returns_none(self):
        self.assertIsNone(relic._filetime_to_dt(9223372036854775807))

    def test_none_returns_none(self):
        self.assertIsNone(relic._filetime_to_dt(None))

    def test_invalid_string_returns_none(self):
        self.assertIsNone(relic._filetime_to_dt("not-a-number"))

    def test_known_date(self):
        # 2024-01-01 00:00:00 UTC in FILETIME
        dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
        ft = relic._dt_to_filetime(dt)
        restored = relic._filetime_to_dt(ft)
        self.assertEqual(restored.year, 2024)
        self.assertEqual(restored.month, 1)
        self.assertEqual(restored.day, 1)


# ---------------------------------------------------------------------------
# Age helper
# ---------------------------------------------------------------------------

class AgeTests(unittest.TestCase):
    def test_age_days(self):
        now = _now()
        dt = now - timedelta(days=45)
        self.assertEqual(relic._age(dt, now), 45)

    def test_age_none(self):
        self.assertIsNone(relic._age(None, _now()))

    def test_age_zero_floor(self):
        now = _now()
        future = now + timedelta(days=5)
        self.assertEqual(relic._age(future, now), 0)


# ---------------------------------------------------------------------------
# UAC flag helper
# ---------------------------------------------------------------------------

class UacTests(unittest.TestCase):
    def test_disabled_flag(self):
        self.assertTrue(relic._uac({"userAccountControl": 514}, relic._UAC_DISABLED))

    def test_not_disabled(self):
        self.assertFalse(relic._uac({"userAccountControl": 512}, relic._UAC_DISABLED))

    def test_never_expires_flag(self):
        self.assertTrue(relic._uac({"userAccountControl": 66048}, relic._UAC_DONT_EXPIRE_PASSWORD))

    def test_missing_uac(self):
        self.assertFalse(relic._uac({}, relic._UAC_DISABLED))

    def test_invalid_uac(self):
        self.assertFalse(relic._uac({"userAccountControl": "bad"}, relic._UAC_DISABLED))


# ---------------------------------------------------------------------------
# Base DN derivation
# ---------------------------------------------------------------------------

class BaseDnTests(unittest.TestCase):
    def test_simple_domain(self):
        self.assertEqual(relic.derive_base_dn("example.com"), "DC=example,DC=com")

    def test_subdomain(self):
        self.assertEqual(relic.derive_base_dn("corp.example.com"), "DC=corp,DC=example,DC=com")

    def test_single_label(self):
        self.assertEqual(relic.derive_base_dn("local"), "DC=local")


# ---------------------------------------------------------------------------
# Group normalisation
# ---------------------------------------------------------------------------

class GroupNormaliseTests(unittest.TestCase):
    def test_single_dn(self):
        result = relic._normalise_groups("CN=Domain Admins,DC=corp,DC=local")
        self.assertEqual(result, ["Domain Admins"])

    def test_list_of_dns(self):
        result = relic._normalise_groups([
            "CN=Group A,DC=corp,DC=local",
            "CN=Group B,DC=corp,DC=local",
        ])
        self.assertEqual(result, ["Group A", "Group B"])

    def test_empty(self):
        self.assertEqual(relic._normalise_groups(None), [])
        self.assertEqual(relic._normalise_groups([]), [])


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class RiskScoringTests(unittest.TestCase):
    def test_disabled_with_groups_is_high(self):
        obj = _obj(disabled=True, groups=["Domain Admins", "VPN Users"])
        risk, reasons = relic.score_object(obj)
        self.assertEqual(risk, "HIGH")
        self.assertTrue(any("disabled account holds" in r for r in reasons))

    def test_service_account_old_password_is_high(self):
        obj = _obj(obj_type="service_account", spns=["HTTP/server.corp.local"], pwd_days_ago=400)
        risk, reasons = relic.score_object(obj)
        self.assertEqual(risk, "HIGH")
        self.assertTrue(any("SPN" in r or "Kerberoast" in r for r in reasons))

    def test_stale_computer_over_365_is_high(self):
        obj = _obj(obj_type="computer", days_ago=400)
        risk, reasons = relic.score_object(obj)
        self.assertEqual(risk, "HIGH")

    def test_never_expires_stale_is_high(self):
        obj = _obj(never_expires=True, days_ago=200)
        risk, reasons = relic.score_object(obj)
        self.assertEqual(risk, "HIGH")
        self.assertTrue(any("non-expiring" in r for r in reasons))

    def test_stale_user_is_medium(self):
        obj = _obj(days_ago=120)
        risk, reasons = relic.score_object(obj)
        self.assertEqual(risk, "MEDIUM")
        self.assertTrue(any("inactive" in r for r in reasons))

    def test_never_expires_active_is_medium(self):
        obj = _obj(never_expires=True, days_ago=10)
        risk, reasons = relic.score_object(obj)
        self.assertEqual(risk, "MEDIUM")

    def test_disabled_no_groups_is_medium(self):
        obj = _obj(disabled=True, groups=[])
        risk, _ = relic.score_object(obj)
        self.assertEqual(risk, "MEDIUM")

    def test_low_risk_object(self):
        obj = _obj(days_ago=0, disabled=False, never_expires=False)
        risk, _ = relic.score_object(obj)
        self.assertEqual(risk, "LOW")


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class DeduplicateTests(unittest.TestCase):
    def test_deduplicates_by_dn(self):
        a = _obj(name="USER1", days_ago=50)
        b = _obj(name="USER1", days_ago=50, groups=["Admins"])  # higher risk
        b["dn"] = a["dn"]  # same DN
        result = relic.deduplicate([a, b])
        self.assertEqual(len(result), 1)

    def test_keeps_higher_risk(self):
        a = _obj(name="USER1", days_ago=10)  # LOW
        b = _obj(name="USER1", days_ago=150)  # MEDIUM
        b["dn"] = a["dn"]
        result = relic.deduplicate([a, b])
        self.assertEqual(result[0]["risk"], "MEDIUM")

    def test_preserves_distinct_objects(self):
        a = _obj(name="USER1")
        b = _obj(name="USER2")
        result = relic.deduplicate([a, b])
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# Dry-run actions
# ---------------------------------------------------------------------------

class DryRunTests(unittest.TestCase):
    def test_disable_dry_run_returns_true(self):
        self.assertTrue(relic.disable_object(MagicMock(), "CN=X,DC=test", dry_run=True))

    def test_apply_action_dry_run_no_calls(self):
        args = MagicMock()
        args.disable = True
        args.dry_run = True
        objects = [_obj(disabled=True, groups=["Admins"])]
        for obj in objects:
            risk, reasons = relic.score_object(obj)
            obj["risk"] = risk
            obj["risk_reasons"] = reasons
        conn = MagicMock()
        relic.apply_action(conn, objects, args)
        conn.modify.assert_not_called()


# ---------------------------------------------------------------------------
# Output (JSON and CSV)
# ---------------------------------------------------------------------------

class JsonOutputTests(unittest.TestCase):
    def test_write_json_structure(self):
        obj = _obj()
        risk, reasons = relic.score_object(obj)
        obj["risk"] = risk
        obj["risk_reasons"] = reasons
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            relic.write_json([obj], path)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["name"], "TESTUSER")
        finally:
            os.unlink(path)

    def test_write_json_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            relic.write_json([], path)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data, [])
        finally:
            os.unlink(path)


class CsvOutputTests(unittest.TestCase):
    def test_write_csv_columns(self):
        obj = _obj(groups=["Admins"])
        risk, reasons = relic.score_object(obj)
        obj["risk"] = risk
        obj["risk_reasons"] = reasons
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", newline="") as fh:
            path = fh.name
        try:
            relic.write_csv([obj], path)
            with open(path, encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 1)
            self.assertIn("name", rows[0])
            self.assertIn("risk", rows[0])
            self.assertIn("group_count", rows[0])
        finally:
            os.unlink(path)

    def test_write_csv_empty_skips(self):
        path = tempfile.mktemp(suffix=".csv")
        relic.write_csv([], path)
        self.assertFalse(os.path.exists(path))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

class ArgParseTests(unittest.TestCase):
    def _args(self, extra=None):
        base = ["--server", "dc.corp.local", "--domain", "corp.local"]
        return relic.parse_args(base + (extra or []))

    def test_defaults(self):
        args = self._args()
        self.assertEqual(args.days, relic.DEFAULT_DAYS)
        self.assertFalse(args.dry_run)
        self.assertFalse(args.disable)
        self.assertFalse(args.ssl)
        self.assertEqual(args.port, relic.DEFAULT_PORT)

    def test_custom_days(self):
        args = self._args(["--days", "180"])
        self.assertEqual(args.days, 180)

    def test_dry_run(self):
        args = self._args(["--dry-run"])
        self.assertTrue(args.dry_run)

    def test_ssl_flag(self):
        args = self._args(["--ssl"])
        self.assertTrue(args.ssl)

    def test_only_flagged(self):
        args = self._args(["--only-flagged"])
        self.assertTrue(args.only_flagged)

    def test_output_flags(self):
        args = self._args(["--output", "out.json", "--output-csv", "out.csv"])
        self.assertEqual(args.output, "out.json")
        self.assertEqual(args.output_csv, "out.csv")

    def test_password_env_flag(self):
        args = self._args(["--username", "svc_relic", "--password-env", "RELIC_BIND_PASSWORD"])
        self.assertEqual(args.password_env, "RELIC_BIND_PASSWORD")

    def test_resolve_password_from_env(self):
        args = self._args(["--username", "svc_relic", "--password-env", "RELIC_BIND_PASSWORD"])
        with unittest.mock.patch.dict(os.environ, {"RELIC_BIND_PASSWORD": "secret-value"}):
            self.assertEqual(relic.resolve_password(args), "secret-value")

    def test_rejects_multiple_password_sources(self):
        args = self._args([
            "--username", "svc_relic",
            "--password", "inline",
            "--password-env", "RELIC_BIND_PASSWORD",
        ])
        with self.assertRaises(SystemExit):
            relic.resolve_password(args)

    def test_scan_targets(self):
        args = self._args(["--users", "--computers", "--disabled", "--never-expires"])
        self.assertTrue(args.users)
        self.assertTrue(args.computers)
        self.assertTrue(args.disabled)
        self.assertTrue(args.never_expires)

    def test_server_required(self):
        with self.assertRaises(SystemExit):
            relic.parse_args([])


if __name__ == "__main__":
    unittest.main()
