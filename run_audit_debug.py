#!/usr/bin/env python3
"""
Runs the REAL audit pipeline (same imports, same functions as audit.py) but
prints results straight to console so there's no confusion with old report
files. Also prints WHERE the report files are written.

USAGE:
  python run_audit_debug.py configs/
  python run_audit_debug.py configs/yourfile.xml
"""
import sys, os, glob, shutil, datetime

# wipe bytecode cache
for d, _, _ in os.walk("."):
    if os.path.basename(d) == "__pycache__":
        shutil.rmtree(d, ignore_errors=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# import the SAME things audit.py imports, the SAME way
from cis_panos.audit import run_checks, load_offline_configs, write_csv
from cis_panos.checks import cis_checks as CC

print("="*70)
print(f"RUN AT: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"cis_checks module: {CC.__file__}")
print(f"CHECKS count: {len(CC.CHECKS)}")
print("="*70)

path = sys.argv[1] if len(sys.argv) > 1 else "configs/"
print(f"\nLoading offline configs from: {path}")

configs = load_offline_configs(path)
print(f"load_offline_configs returned {len(configs)} config(s)\n")

if not configs:
    print("!! NO CONFIGS LOADED. Check the path. Files present:")
    for f in glob.glob(os.path.join(path if os.path.isdir(path) else ".", "*.xml")):
        print(f"   {f}")
    sys.exit(1)

all_rows = []
for label, cfg in configs:
    print(f"Evaluating: {label}")
    print(f"   cfg root tag: <{cfg.tag}>, top-level: {[c.tag for c in cfg]}")
    rows = run_checks(cfg, label)
    all_rows += rows
    from collections import Counter
    print(f"   result summary: {dict(Counter(r['result'] for r in rows))}\n")

# Print the rule-relevant checks directly
print("="*70)
print("RULE / PROFILE CHECK RESULTS (live from this run):")
print("="*70)
for row in all_rows:
    if row["id"].startswith(("5.2","6.","7.")):
        print(f"  {row['id']:6} [{row['result']:7}] {row['evidence'][:60]}")

# Write CSV and report exactly where
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
out_dir = "reports"
csv_path = write_csv(all_rows, out_dir, ts)
print("\n" + "="*70)
print(f"CSV WRITTEN TO: {os.path.abspath(csv_path)}")
print("Open THIS file (note the timestamp) — not an older report.")
print("="*70)
