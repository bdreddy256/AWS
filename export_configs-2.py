#!/usr/bin/env python3
"""
Config export helper for CIS PAN-OS audit.

Pulls TWO things from each firewall and merges into one XML:
  1. show config merged         → device settings (mgmt, password, NTP, SNMP, etc.)
  2. show config pushed-shared-policy → Panorama-pushed security rules + SGPs

Why two calls?
  - merged config has the device-level settings
  - pushed-shared-policy has the actual security rules and profiles
    pushed from Panorama (these don't appear in merged config on the FW)

ZERO DEPENDENCIES. Read-only. Python 3.8+

USAGE
  python export_configs.py --target firewall --host 10.0.0.1 --apikey "$KEY" --out ./configs/
  python export_configs.py --target panorama --host 10.0.0.9 --apikey "$KEY" --out ./configs/
"""

import argparse
import os
import ssl
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def _api_get(host, params, verify_tls=False, timeout=30):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{host}/api/?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(urllib.request.Request(url),
                                context=ctx, timeout=timeout) as r:
        data = r.read()
    root = ET.fromstring(data)
    if root.get("status") != "success":
        raise RuntimeError(root.findtext(".//msg") or "API error")
    return root


def save_config(cfg_element, out_dir, label):
    os.makedirs(out_dir, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)
    path = os.path.join(out_dir, f"{safe}.xml")
    xml_str = ET.tostring(cfg_element, encoding="unicode")
    with open(path, "w") as f:
        f.write(xml_str)
    return path


def export_firewall(host, apikey, out_dir, verify_tls=False, label=None):
    """
    Export merged config + pushed-shared-policy from a single firewall.
    Combines both into one XML for offline auditing.
    """
    label = label or host
    print(f"  [*] {label}")

    # --- 1. Get device settings from merged config ---
    print(f"      Pulling merged config (device settings)...")
    try:
        r = _api_get(host, {
            "type": "op",
            "cmd": "<show><config><merged></merged></config></show>",
            "key": apikey
        }, verify_tls)
        merged_cfg = r.find(".//result/config")
        if merged_cfg is None:
            merged_cfg = r.find(".//result")
        if merged_cfg is None:
            print(f"      ! merged config: no result element returned")
            merged_cfg = ET.Element("config")
    except Exception as e:
        print(f"      ! merged config error: {e}")
        merged_cfg = ET.Element("config")

    # --- 2. Get Panorama-pushed security rules ---
    print(f"      Pulling pushed-shared-policy (Panorama rules + SGPs)...")
    pushed_policy = None
    try:
        r = _api_get(host, {
            "type": "op",
            "cmd": "<show><config><pushed-shared-policy></pushed-shared-policy></config></show>",
            "key": apikey
        }, verify_tls)
        # Result structure: <result><policy><panorama>...</panorama></policy></result>
        pushed_policy = r.find(".//result/policy")
        if pushed_policy is None:
            pushed_policy = r.find(".//result")
        if pushed_policy is not None:
            print(f"      ✓ pushed-shared-policy retrieved")
        else:
            print(f"      ! pushed-shared-policy: no policy element in result")
    except Exception as e:
        print(f"      ! pushed-shared-policy error: {e}")

    # --- 3. Merge: inject pushed policy into merged config ---
    if pushed_policy is not None:
        # Attach as <pushed_policy> sub-element on merged config root
        # cis_checks.py will look here
        pushed_elem = ET.SubElement(merged_cfg, "pushed_policy")
        for child in pushed_policy:
            pushed_elem.append(child)

    # --- 4. Save ---
    p = save_config(merged_cfg, out_dir, label)
    print(f"      saved → {p}\n")
    return p


def main():
    ap = argparse.ArgumentParser(
        description="Export PAN-OS config + Panorama pushed policy for offline CIS audit")
    ap.add_argument("--target", choices=["panorama", "firewall"], required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--apikey", required=True)
    ap.add_argument("--out", default="configs")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    if args.target == "firewall":
        print(f"[*] Exporting from firewall: {args.host}\n")
        export_firewall(args.host, args.apikey, args.out, args.verify_tls)

    else:
        print(f"[*] Enumerating connected devices via Panorama: {args.host}\n")
        r = _api_get(args.host, {
            "type": "op",
            "cmd": "<show><devices><connected></connected></devices></show>",
            "key": args.apikey
        }, args.verify_tls)

        devs = []
        for e in r.findall(".//devices/entry"):
            serial = e.get("name") or e.findtext("serial")
            hostname = e.findtext("hostname") or serial
            devs.append((serial, hostname))

        print(f"Found {len(devs)} connected device(s)\n")

        for serial, hostname in devs:
            label = f"{hostname}_{serial}"
            # For Panorama-proxied pull, we call the FW via Panorama's target param
            # but pushed-shared-policy must be pulled directly from each FW
            # So we use the FW's management IP if available, else skip policy pull
            mgmt_ip = None
            for e in r.findall(f".//devices/entry[@name='{serial}']"):
                mgmt_ip = e.findtext("ip-address") or e.findtext("mgmt-ip")

            if mgmt_ip:
                export_firewall(mgmt_ip, args.apikey, args.out, args.verify_tls, label=label)
            else:
                # Fallback: pull merged config via Panorama proxy (no pushed policy)
                print(f"  [*] {label} (no mgmt IP — pulling via Panorama proxy, policies may be missing)")
                try:
                    r2 = _api_get(args.host, {
                        "type": "op",
                        "cmd": "<show><config><merged></merged></config></show>",
                        "target": serial,
                        "key": args.apikey
                    }, args.verify_tls)
                    cfg = r2.find(".//result/config")
                    if cfg is None:
                        print("      ! no config"); continue
                    p = save_config(cfg, args.out, label)
                    print(f"      saved → {p}\n")
                except Exception as e:
                    print(f"      ! error: {e}\n")

    print("Done.")


if __name__ == "__main__":
    main()
