#!/usr/bin/env python3
"""
End-to-end self-test. Point it at your EXPORTED config file (the one you
confirmed contains rules/profiles). It reports, step by step, exactly where
rules/profile-groups are or aren't being found — using the SAME code path
the audit uses.

USAGE:
  python selftest.py configs/<your-exported-file>.xml
"""
import sys, os, glob
import xml.etree.ElementTree as ET

# Force-load the LOCAL cis_checks (not any stale installed copy) and show its path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Nuke any bytecode cache first
import shutil
for d, _, _ in os.walk("."):
    if os.path.basename(d) == "__pycache__":
        shutil.rmtree(d, ignore_errors=True)

from cis_panos.checks import cis_checks as CC
print(f"[i] Using cis_checks from: {CC.__file__}")
print(f"[i] Has _get_all_profile_groups: {hasattr(CC, '_get_all_profile_groups')}")
print(f"[i] Has _rule_pg_name:          {hasattr(CC, '_rule_pg_name')}")
print()

if len(sys.argv) > 1:
    f = sys.argv[1]
else:
    files = glob.glob("configs/*.xml")
    if not files:
        sys.exit("Usage: python selftest.py <config.xml>   (none found in configs/)")
    f = files[0]
    print(f"[i] No file given; using {f}\n")

# --- replicate audit.py's exact loading logic ---
root = ET.parse(f).getroot()
print(f"[1] File: {f}")
print(f"    Root element tag: <{root.tag}>  attribs={dict(root.attrib)}")

cfg = root if root.tag == "config" else root.find(".//config")
if cfg is None:
    sys.exit("    !! audit.py would SKIP this file: no <config> element found")
print(f"    audit.py binds cfg = <{cfg.tag}>  (this is what every check receives)")
print()

# --- what the checks see ---
print("[2] Top-level children under cfg:")
for c in cfg:
    print(f"      <{c.tag}> ({len(list(c))} children)")
print()

# --- does pushed_policy/panorama exist under cfg? ---
print("[3] Looking for pushed_policy/panorama under cfg:")
pp = cfg.find("pushed_policy")
print(f"      cfg.find('pushed_policy')            -> {'FOUND' if pp is not None else 'None'}")
pano = cfg.find("pushed_policy/panorama")
print(f"      cfg.find('pushed_policy/panorama')   -> {'FOUND' if pano is not None else 'None'}")
pano2 = cfg.find(".//panorama")
print(f"      cfg.find('.//panorama')              -> {'FOUND' if pano2 is not None else 'None'}")
print()

# --- run the real helpers ---
print("[4] Real helper results (same functions the checks call):")
rules = CC._get_all_rules(cfg)
pgs   = CC._get_all_sgps(cfg)
print(f"      _get_all_rules(cfg)  -> {len(rules)} rules")
for r in rules[:5]:
    print(f"          rule: {r.get('name'):40} action={CC._rule_action(r)} pg={CC._rule_pg_name(r)}")
print(f"      _get_all_sgps(cfg)   -> {len(pgs)} profile-groups")
for pg in pgs[:5]:
    profs,_ = CC._sgp_profiles(pg)
    ne = {k:v for k,v in profs.items() if v}
    print(f"          pg: {pg.get('name'):20} {ne}")
print()

# --- if zero, probe WHERE rules actually are ---
if not rules:
    print("[5] Rules came back ZERO. Probing every <rules> element in the file:")
    found_any = False
    for rules_el in cfg.iter("rules"):
        entries = rules_el.findall("entry")
        if entries:
            found_any = True
            # reconstruct path by walking (ElementTree has no parent, so approximate)
            print(f"      <rules> with {len(entries)} entries; first entry name={entries[0].get('name')!r}")
    if not found_any:
        print("      No <rules> element with <entry> children found ANYWHERE under cfg.")
        print("      -> The exported file does NOT actually contain security rules under this root.")
    print()
    print("[5b] All distinct element tags containing 'rulebase' or 'panorama':")
    for tag in sorted({e.tag for e in cfg.iter() if 'rulebase' in e.tag or 'panorama' in e.tag}):
        print(f"        <{tag}>")
else:
    print("[5] Rules found correctly. Running all 55 checks:")
    from collections import Counter
    res = []
    for chk in CC.CHECKS:
        try: r,e = chk['fn'](cfg)
        except Exception as ex: r,e = "ERROR", str(ex)[:60]
        res.append((chk['id'], r, e))
    print("      SUMMARY:", dict(Counter(r for _,r,_ in res)))
    print("      Sample rule/profile checks:")
    for cid,r,e in res:
        if cid in ("5.2","6.2","6.7","6.9","7.2","7.3","7.4"):
            print(f"        {cid:5} [{r:6}] {e[:52]}")
