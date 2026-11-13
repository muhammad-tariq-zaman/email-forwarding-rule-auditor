"""Audit mailbox forwarding rules for external forwards and gaps.

Usage: python3 main.py rules.csv [--internal-domains company.local,example.com]
CSV columns: mailbox,rule_name,forward_to,enabled.
- EXTERNAL: the forward target's domain is not in --internal-domains
  (only checked when internal domains are given).
- NO TARGET: forward_to is empty.
- DISABLED: the rule is not enabled (enabled is not yes).
- OK: enabled, has a target, and the target is internal.
Rules with problems are listed first.
"""
import argparse, csv, sys

def audit(rows, internal_domains=()):
    internal = {d.strip().lower() for d in internal_domains}
    out = []
    for row in rows:
        mailbox = row["mailbox"].strip()
        rule = row["rule_name"].strip()
        target = row["forward_to"].strip()
        enabled = row["enabled"].strip().lower() in ("yes", "y", "true", "1")
        flags = []
        if not target:
            flags.append("NO TARGET")
        elif internal and target.rsplit("@", 1)[-1].lower() not in internal:
            flags.append("EXTERNAL")
        if not enabled:
            flags.append("DISABLED")
        out.append((mailbox, rule, target, flags))
    out.sort(key=lambda r: (len(r[3]) == 0, r[0], r[1]))
    return out

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--internal-domains", default="",
                        help="comma-separated internal email domains")
    args = parser.parse_args(argv)
    internal = [d for d in args.internal_domains.split(",") if d.strip()]
    with open(args.path, newline="", encoding="utf-8") as f:
        results = audit(list(csv.DictReader(f)), internal)
    for mailbox, rule, target, flags in results:
        shown = target if target else "(none)"
        flag_text = ", ".join(flags) if flags else "OK"
        print(f"{mailbox} '{rule}' -> {shown}: {flag_text}")
    print(f"{sum(1 for *_, f in results if 'EXTERNAL' in f)} rule(s) forward externally, "
          f"{sum(1 for *_, f in results if 'NO TARGET' in f)} rule(s) with no target.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
