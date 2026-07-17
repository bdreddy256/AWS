#!/usr/bin/env python3
"""
Inspect PAN-OS config paths — reads directly from a firewall OR a file.
Read-only (show config only). Stdlib only.

USAGE
  # live firewall (merged/effective running config):
  python inspect_live.py --host <FW-IP> --apikey "<KEY>"
  # a specific element (default: password-complexity):
  python inspect_live.py --host <FW-IP> --apikey "<KEY>" --tag minimum-length
  # offline file:
  python inspect_live.py --file config.xml --tag minimum-length
"""
import argparse, ssl, urllib.parse, urllib.request
import xml.etree.ElementTree as ET


def get_live_config(host, apikey, verify_tls=False):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # merged = effective running config (includes Panorama-pushed template values)
    params = {"type": "op",
              "cmd": "<show><config><merged></merged></config></show>",
              "key": apikey}
    url = f"https://{host}/api/?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(urllib.request.Request(url), context=ctx, timeout=30) as r:
        root = ET.fromstring(r.read())
    if root.get("status") != "success":
        raise SystemExit("API error: " + (root.findtext(".//msg") or "unknown"))
    cfg = root.find(".//result/config")
    if cfg is None:
        # some versions wrap differently; fall back to result
        cfg = root.find(".//result")
    return cfg


def path_to(node, target_tag, trail=""):
    p = f"{trail}/{node.tag}"
    if node.tag == target_tag:
        val = (node.text or "").strip()
        print(f"  PATH: {p}" + (f"  = {val!r}" if val else "  (container)"))
    for c in node:
        path_to(c, target_tag, p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host")
    ap.add_argument("--apikey")
    ap.add_argument("--file")
    ap.add_argument("--tag", default="password-complexity",
                    help="element name to locate (default: password-complexity)")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    if args.file:
        root = ET.parse(args.file).getroot()
        root = root if root.tag == "config" else (root.find(".//config") or root)
    elif args.host and args.apikey:
        print(f"[*] Pulling merged config from {args.host} ...")
        root = get_live_config(args.host, args.apikey, args.verify_tls)
    else:
        raise SystemExit("Provide --file OR (--host and --apikey)")

    print(f"\n=== locating <{args.tag}> ===")
    hits = list(root.iter(args.tag))
    if not hits:
        print(f"  NOT FOUND anywhere in config.")
    path_to(root, args.tag)

    # also always show the two password fields for convenience
    for t in ("minimum-length", "enabled"):
        print(f"\n=== locating <{t}> ===")
        if not list(root.iter(t)):
            print("  NOT FOUND")
        path_to(root, t)


if __name__ == "__main__":
    main()
