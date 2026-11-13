import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import audit

def row(mailbox, rule, target, enabled):
    return {"mailbox": mailbox, "rule_name": rule, "forward_to": target,
            "enabled": enabled}

class TestForwardingRuleAuditor(unittest.TestCase):
    def test_external_flagged(self):
        r = audit([row("ali", "To personal", "ali@gmail.com", "yes")],
                  internal_domains=["company.local"])
        self.assertEqual(r[0][3], ["EXTERNAL"])

    def test_internal_ok(self):
        r = audit([row("sara", "To manager", "mgr@company.local", "yes")],
                  internal_domains=["company.local"])
        self.assertEqual(r[0][3], [])

    def test_no_target_flagged(self):
        r = audit([row("omar", "Old rule", "", "yes")])
        self.assertEqual(r[0][3], ["NO TARGET"])

    def test_disabled_flagged(self):
        r = audit([row("omar", "Old rule", "x@company.local", "no")],
                  internal_domains=["company.local"])
        self.assertEqual(r[0][3], ["DISABLED"])

    def test_no_internal_list_no_external_flag(self):
        r = audit([row("ali", "To personal", "ali@gmail.com", "yes")])
        self.assertEqual(r[0][3], [])

    def test_multiple_flags(self):
        r = audit([row("omar", "Old rule", "", "no")])
        self.assertEqual(r[0][3], ["NO TARGET", "DISABLED"])

    def test_problems_first(self):
        r = audit([row("zed", "Good", "zed@company.local", "yes"),
                   row("amy", "Bad", "amy@gmail.com", "yes")],
                  internal_domains=["company.local"])
        self.assertEqual(r[0][0], "amy")

    def test_empty_input(self):
        self.assertEqual(audit([]), [])
