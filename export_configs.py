#!/usr/bin/env python3
"""
Config export helper — pulls running config XML from Panorama or a firewall
and saves one .xml per device into a folder, ready for offline auditing.

Useful when your security policy prefers pulling configs once (change-controlled)
and running the audit offline, rather than scanning the live mgmt plane repeatedly.

ZERO DEPENDENCIES. Read-only (show config only).

USAGE
  python export_configs.py --target panorama --host 10.0.0.9 --apikey "$KEY" --out ./configs/
  python export_configs.py --target firewall --host 10.0.0.1 --apikey "$KEY" --out ./configs/
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
    ET.ElementTree(cfg_element).write(path, encoding="unicode"
                                      if hasattr(ET, "indent") else None)
    # ElementTree.write with encoding='unicode' writes str to a text file only via open;
    # simplest portable path: serialize to string then write.
    xml_str = ET.tostring(cfg_element, encoding="unicode")
    with open(path, "w") as f:
        f.write(xml_str)
    return path


def main():
    ap = argparse.ArgumentParser(description="Export PAN-OS configs for offline audit")
    ap.add_argument("--target", choices=["panorama", "firewall"], required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--apikey", required=True)
    ap.add_argument("--out", default="configs")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    if args.target == "firewall":
        print(f"[*] Exporting config from firewall {args.host}")
        root = _api_get(args.host, {"type": "config", "action": "show",
                        "xpath": "/config", "key": args.apikey}, args.verify_tls)
        cfg = root.find(".//result/config")
        if cfg is None:
            sys.exit("No config returned.")
        p = save_config(cfg, args.out, args.host)
        print(f"    saved {p}")
    else:
        print(f"[*] Enumerating devices via Panorama {args.host}")
        root = _api_get(args.host, {"type": "op",
            "cmd": "<show><devices><connected></connected></devices></show>",
            "key": args.apikey}, args.verify_tls)
        devs = [(e.get("name") or e.findtext("serial"),
                 e.findtext("hostname") or e.get("name"))
                for e in root.findall(".//devices/entry")]
        print(f"    found {len(devs)} device(s)")
        for serial, hostname in devs:
            print(f"    - {hostname} ({serial})")
            try:
                r = _api_get(args.host, {"type": "config", "action": "show",
                    "xpath": "/config", "target": serial,
                    "key": args.apikey}, args.verify_tls)
                cfg = r.find(".//result/config")
                if cfg is None:
                    print("      ! no config"); continue
                p = save_config(cfg, args.out, f"{hostname}_{serial}")
                print(f"      saved {p}")
            except Exception as e:
                print(f"      ! error: {e}")
    print("Done.")


if __name__ == "__main__":
    main()
