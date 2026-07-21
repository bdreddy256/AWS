#!/usr/bin/env python3
"""
CIS PAN-OS Compliance Audit Tool  (dependency-free)
===================================================
Pulls running config from Panorama or a firewall (read-only), evaluates it
against CIS PAN-OS benchmark checks, and produces timestamped CSV + HTML + PDF
reports — evidence for #54 (scan), #86 (annual review), #87 (non-compliant pop).

ZERO EXTERNAL DEPENDENCIES. Pure Python standard library. No pip install.
Requires Python 3.8+ (already on most systems).

CONNECTION MODES
  --offline <file-or-dir>       Evaluate exported config XML. No network.
                                (Recommended for banks — no live prod scan.)
  --target firewall --host H --apikey K
                                Pull one firewall's running config directly.
  --target panorama --host H --apikey K
                                Enumerate + pull every managed device via Panorama.

READ-ONLY: only issues 'show config' API calls. Never commits.

GET A READ-ONLY API KEY (use a superreader / read-only admin):
  curl -k "https://<host>/api/?type=keygen&user=<user>&password=<pass>"

USAGE
  python -m cis_panos.audit --offline ./configs/ --out reports/
  python -m cis_panos.audit --target firewall --host 10.0.0.1 --apikey "$PANKEY"
  python -m cis_panos.audit --target panorama --host 10.0.0.9 --apikey "$PANKEY"

Validate check logic against your CIS PDF before using as sole audit evidence.
"""

import argparse
import csv
import datetime
import glob
import html
import os
import ssl
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

# Support both `python -m cis_panos.audit` and `python cis_panos/audit.py`
try:
    from .checks.cis_checks import CHECKS
    from .pdf_writer import build_pdf
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from checks.cis_checks import CHECKS
    from pdf_writer import build_pdf


# ----------------------------- API layer -----------------------------

def _api_get(host, params, verify_tls=False, timeout=30):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{host}/api/?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        data = r.read()
    root = ET.fromstring(data)
    if root.get("status") != "success":
        msg = root.findtext(".//msg") or "unknown API error"
        raise RuntimeError(f"API error from {host}: {msg}")
    return root


def _fetch_pushed_policy(host, apikey, verify_tls=False, target=None):
    """
    Pull 'show config pushed-shared-policy' and return the <panorama> element
    (the block containing pre/post-rulebase security rules, profile-groups,
    and profile definitions). Returns None if unavailable.
    """
    params = {
        "type": "op",
        "cmd": "<show><config><pushed-shared-policy></pushed-shared-policy></config></show>",
        "key": apikey}
    if target:
        params["target"] = target
    try:
        root = _api_get(host, params, verify_tls)
    except Exception as e:
        print(f"    ! pushed-shared-policy pull failed: {e}", file=sys.stderr)
        return None
    # API returns <response><result><policy><panorama>...  (names vary slightly
    # by PAN-OS version). Locate <panorama> wherever it sits.
    pano = root.find(".//panorama")
    if pano is not None:
        return pano
    policy = root.find(".//result/policy") or root.find(".//result")
    return policy  # caller wraps if needed


def _stitch_pushed_policy(cfg, pano_elem):
    """Attach pushed policy under cfg as  pushed_policy/panorama  (checks expect this)."""
    if cfg is None or pano_elem is None:
        return cfg
    pushed = ET.SubElement(cfg, "pushed_policy")
    if pano_elem.tag == "panorama":
        pushed.append(pano_elem)
    else:
        wrapper = ET.SubElement(pushed, "panorama")
        for child in list(pano_elem):
            wrapper.append(child)
    return cfg


def _fetch_effective_running(host, apikey, verify_tls=False, target=None):
    """
    Pull 'show config effective-running' - PAN-OS's single authoritative view of
    what is actually running on the device (local + template/stack + Panorama-
    pushed rules/objects, already merged by the firewall itself).

    Returns the <config> element, or None if unavailable / empty.
    """
    params = {
        "type": "op",
        "cmd": "<show><config><effective-running></effective-running></config></show>",
        "key": apikey}
    if target:
        params["target"] = target
    try:
        root = _api_get(host, params, verify_tls)
    except Exception as e:
        print(f"    ! effective-running pull failed: {e}", file=sys.stderr)
        return None
    cfg = root.find(".//result/config")
    if cfg is None:
        cfg = root.find(".//result")
    return cfg


def _config_has_policy(cfg):
    """True if this config already contains security rules inline (no stitching needed)."""
    if cfg is None:
        return False
    return cfg.find(".//security/rules/entry") is not None


def _report_pull(cfg, label="effective-running"):
    n_rules = len(cfg.findall(".//security/rules/entry")) if cfg is not None else 0
    n_pg = len(cfg.findall(".//profile-group/entry")) if cfg is not None else 0
    n_wf = len(cfg.findall(".//setting/wildfire/file-size-limit/entry")) if cfg is not None else 0
    print(f"    {label}: {n_rules} security rules, {n_pg} profile-groups, "
          f"{n_wf} wildfire file-size entries")


def get_firewall_running_config(host, apikey, verify_tls=False):
    # PREFERRED: effective-running is the firewall's own fully-merged running
    # config (device settings + template/stack + Panorama-pushed rules/objects).
    # It resolves per-device template-stack layering natively, so it's the most
    # accurate source and needs no manual stitching.
    cfg = _fetch_effective_running(host, apikey, verify_tls)
    if _config_has_policy(cfg):
        print("    [source: effective-running - single authoritative pull]")
        _report_pull(cfg)
        return cfg

    # FALLBACK: older/lower-priv setups where effective-running is unavailable or
    # returns no policy. Reconstruct from merged + pushed-shared-policy.
    print("    [source: effective-running lacked policy -> falling back to merged + pushed-shared-policy]")
    root = _api_get(host, {
        "type": "op",
        "cmd": "<show><config><merged></merged></config></show>",
        "key": apikey}, verify_tls)
    cfg = root.find(".//result/config")
    if cfg is None:
        cfg = root.find(".//result")
    if cfg is None:
        raise RuntimeError(f"No config returned from {host}")

    pano = _fetch_pushed_policy(host, apikey, verify_tls)
    _stitch_pushed_policy(cfg, pano)
    _report_pull(cfg, "merged+pushed")
    return cfg


def list_panorama_devices(host, apikey, verify_tls=False):
    root = _api_get(host, {
        "type": "op",
        "cmd": "<show><devices><connected></connected></devices></show>",
        "key": apikey}, verify_tls)
    devs = []
    for e in root.findall(".//devices/entry"):
        serial = e.get("name") or e.findtext("serial") or "unknown"
        hostname = e.findtext("hostname") or serial
        devs.append((serial, hostname))
    return devs


def get_device_config_via_panorama(host, apikey, serial, verify_tls=False):
    # PREFERRED: effective-running proxied to the device via target=<serial>.
    cfg = _fetch_effective_running(host, apikey, verify_tls, target=serial)
    if _config_has_policy(cfg):
        print("      [source: effective-running]")
        _report_pull(cfg)
        return cfg

    # FALLBACK: merged + pushed-shared-policy proxied via Panorama.
    print("      [source: effective-running lacked policy -> merged + pushed-shared-policy]")
    root = _api_get(host, {
        "type": "op",
        "cmd": "<show><config><merged></merged></config></show>",
        "target": serial, "key": apikey}, verify_tls)
    cfg = root.find(".//result/config")
    if cfg is None:
        cfg = root.find(".//result")
    if cfg is None:
        raise RuntimeError(f"No config for device {serial} via Panorama")

    pano = _fetch_pushed_policy(host, apikey, verify_tls, target=serial)
    _stitch_pushed_policy(cfg, pano)
    _report_pull(cfg, "merged+pushed")
    return cfg


# ----------------------------- evaluation -----------------------------


def load_exemptions(config_path="config_audit_exemptions.txt"):
    """Load exempt/N/A controls from config file."""
    exemptions = {}
    if not os.path.isfile(config_path):
        return exemptions
    try:
        with open(config_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    ctrl, reason = line.split("=", 1)
                    exemptions[ctrl.strip()] = reason.strip()
    except Exception as e:
        print(f"Warning: Could not load exemptions: {e}", file=sys.stderr)
    return exemptions


def apply_exemptions(rows, exemptions):
    """Convert FAIL to N/A for exempt controls."""
    for row in rows:
        if row["id"] in exemptions:
            if row["result"] in ["FAIL", "ERROR"]:
                row["result"] = "N/A"
                row["evidence"] = f"Not applicable - {exemptions[row['id']]}"
    return rows



def run_checks(config_root, device_label):
    rows = []
    for chk in CHECKS:
        try:
            result, evidence = chk["fn"](config_root)
        except Exception as e:
            result, evidence = "ERROR", f"check exception: {e}"
        rows.append({"device": device_label, "id": chk["id"],
                     "title": chk["title"], "severity": chk["severity"],
                     "result": result, "evidence": evidence})
    return rows


def load_offline_configs(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.xml")))
    elif os.path.isfile(path):
        files = [path]
    else:
        raise SystemExit(f"Path not found: {path}")
    if not files:
        raise SystemExit(f"No .xml config files found at: {path}")
    out = []
    for f in files:
        root = ET.parse(f).getroot()
        cfg = root if root.tag == "config" else root.find(".//config")
        if cfg is None:
            print(f"  ! skipping {f}: no <config> element", file=sys.stderr)
            continue
        label = os.path.splitext(os.path.basename(f))[0]
        out.append((label, cfg))
    return out


# ----------------------------- reporting -----------------------------

RESULT_ORDER = {"FAIL": 0, "ERROR": 1, "MANUAL": 2, "PASS": 3}


def _sorted(rows):
    return sorted(rows, key=lambda x: (x["device"],
                  RESULT_ORDER.get(x["result"], 9), x["id"]))


def _summary(rows):
    s = {"PASS": 0, "FAIL": 0, "MANUAL": 0, "ERROR": 0}
    for r in rows:
        s[r["result"]] = s.get(r["result"], 0) + 1
    return s


def _group_by_device(rows):
    """Return list of (device, [rows]) preserving device sort + in-device result/id order."""
    from collections import OrderedDict
    grouped = OrderedDict()
    for r in _sorted(rows):
        grouped.setdefault(r["device"], []).append(r)
    return list(grouped.items())


def _device_summary(dev_rows):
    """Summary counts for one device's rows."""
    s = {}
    for r in dev_rows:
        s[r["result"]] = s.get(r["result"], 0) + 1
    return s


def write_csv(rows, out_dir, ts):
    p = os.path.join(out_dir, f"cis_panos_report_{ts}.csv")
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        header = ["device", "id", "title", "severity", "result", "evidence"]
        for i, (device, dev_rows) in enumerate(_group_by_device(rows)):
            ds = _device_summary(dev_rows)
            summary = "  ".join(f"{k}={v}" for k, v in sorted(ds.items()))
            if i > 0:
                w.writerow([])  # blank separator between devices
            # Device banner rows
            w.writerow([f"===== DEVICE: {device} =====", "", "", "", "", summary])
            w.writerow(header)
            for r in dev_rows:
                w.writerow([r["device"], r["id"], r["title"],
                            r["severity"], r["result"], r["evidence"]])
    return p


def write_html(rows, out_dir, ts, meta):
    p = os.path.join(out_dir, f"cis_panos_report_{ts}.html")
    s = _summary(rows)
    groups = _group_by_device(rows)
    devices = [d for d, _ in groups]
    color = {"PASS": "#1a7f37", "FAIL": "#cf222e",
             "MANUAL": "#9a6700", "ERROR": "#8250df", "N/A": "#9a6700",
             "WARNING": "#bc4c00", "INFO": "#0969da"}
    b = [f"""<!doctype html><html><head><meta charset="utf-8">
<title>CIS PAN-OS Compliance Report {html.escape(ts)}</title><style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1c2128}}
 h1{{font-size:20px;margin:0 0 4px}} .meta{{color:#57606a;font-size:13px;margin-bottom:16px}}
 h2.device{{font-size:16px;margin:28px 0 4px;padding:8px 12px;background:#0969da;color:#fff;border-radius:6px}}
 .cards{{display:flex;gap:12px;margin:10px 0}}
 .card{{border:1px solid #d0d7de;border-radius:8px;padding:8px 14px;min-width:70px}}
 .card .n{{font-size:20px;font-weight:600}} .card .l{{font-size:12px;color:#57606a}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}
 th,td{{border:1px solid #d0d7de;padding:6px 8px;text-align:left;vertical-align:top}}
 th{{background:#f6f8fa}} .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
 tr:hover{{background:#f6f8fa}}
 .toc{{font-size:13px;margin:8px 0 20px}} .toc a{{color:#0969da;text-decoration:none;margin-right:14px}}
</style></head><body>
<h1>CIS Palo Alto Firewall Benchmark — Compliance Report</h1>
<div class="meta">Generated: {html.escape(meta['generated'])} &nbsp;|&nbsp;
 Benchmark: {html.escape(meta['benchmark'])} &nbsp;|&nbsp;
 Source: {html.escape(meta['source'])} &nbsp;|&nbsp; Devices: {len(devices)}</div>
<div class="meta"><b>Overall:</b>"""]
    for k in ["FAIL", "MANUAL", "ERROR", "N/A", "PASS"]:
        if s.get(k, 0):
            b.append(f" <span style='color:{color.get(k,'#57606a')}'>{k}={s.get(k,0)}</span>")
    b.append('</div>')

    # Table of contents (jump links) when more than one device
    if len(devices) > 1:
        b.append('<div class="toc"><b>Jump to device:</b> ')
        for i, d in enumerate(devices):
            b.append(f'<a href="#dev{i}">{html.escape(d)}</a>')
        b.append('</div>')

    # One section per device
    for i, (device, dev_rows) in enumerate(groups):
        ds = _device_summary(dev_rows)
        b.append(f'<h2 class="device" id="dev{i}">{html.escape(device)}</h2>')
        b.append('<div class="cards">')
        for k in ["FAIL", "MANUAL", "ERROR", "N/A", "PASS"]:
            if ds.get(k, 0):
                b.append(f'<div class="card"><div class="n" style="color:{color.get(k,"#57606a")}">'
                         f'{ds.get(k,0)}</div><div class="l">{k}</div></div>')
        b.append('</div>')
        b.append('<table><tr><th>Control</th><th>Title</th>'
                 '<th>Severity</th><th>Result</th><th>Evidence</th></tr>')
        for r in dev_rows:
            bg = color.get(r["result"], "#57606a")
            b.append(f"<tr><td>{html.escape(r['id'])}</td>"
                     f"<td>{html.escape(r['title'])}</td>"
                     f"<td>{html.escape(r['severity'])}</td>"
                     f"<td><span class='badge' style='background:{bg}'>{r['result']}</span></td>"
                     f"<td>{html.escape(r['evidence'])}</td></tr>")
        b.append('</table>')

    b.append('<p style="color:#57606a;font-size:11px;margin-top:16px">'
             'Self-generated assessment tool. Validate check logic against the CIS '
             'PAN-OS benchmark PDF before relying on this as sole audit evidence.</p>'
             '</body></html>')
    with open(p, "w", encoding="utf-8") as f:
        f.write("".join(b))
    return p


def write_pdf(rows, out_dir, ts, meta):
    p = os.path.join(out_dir, f"cis_panos_report_{ts}.pdf")
    s = _summary(rows)
    groups = _group_by_device(rows)
    meta_lines = [
        f"Generated: {meta['generated']}",
        f"Benchmark: {meta['benchmark']}",
        f"Source: {meta['source']}",
        f"Devices: {len(groups)}",
        f"Overall: FAIL={s.get('FAIL',0)}  N/A={s.get('N/A',0)}  "
        f"ERROR={s.get('ERROR',0)}  PASS={s.get('PASS',0)}",
    ]
    headers = ["Device", "Control", "Title", "Sev", "Result", "Evidence"]
    table = []
    for device, dev_rows in groups:
        ds = _device_summary(dev_rows)
        summary = "  ".join(f"{k}={v}" for k, v in sorted(ds.items()))
        # device banner row (spans visually via first cells)
        table.append((f"== {device} ==", "", "", "", "", summary))
        for r in dev_rows:
            table.append((r["device"], r["id"], r["title"], r["severity"],
                          r["result"], r["evidence"]))
    build_pdf(p, "CIS PAN-OS Compliance Report", meta_lines, table, headers)
    return p


# ----------------------------- main -----------------------------

def main():
    ap = argparse.ArgumentParser(description="CIS PAN-OS compliance audit tool")
    ap.add_argument("--target", choices=["panorama", "firewall"])
    ap.add_argument("--host")
    ap.add_argument("--apikey")
    ap.add_argument("--offline")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--benchmark",
                    default="CIS Palo Alto Firewall 11 Benchmark v1.2.0 L1")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    # Version banner — confirms you are running the FIXED file (UTF-8 report writing).
    print("[*] cis_panos.audit  BUILD 2026-07-21-utf8  (UTF-8 report writing)")
    print(f"[*] running file: {os.path.abspath(__file__)}")

    os.makedirs(args.out, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    generated = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    all_rows, source = [], ""

    if args.offline:
        source = f"offline export: {args.offline}"
        print(f"[*] Loading offline configs from {args.offline}")
        for label, cfg in load_offline_configs(args.offline):
            print(f"    - evaluating {label}")
            all_rows += run_checks(cfg, label)
    elif args.target == "firewall":
        if not (args.host and args.apikey):
            ap.error("--target firewall requires --host and --apikey")
        source = f"firewall {args.host}"
        print(f"[*] Pulling running config from firewall {args.host}")
        all_rows += run_checks(
            get_firewall_running_config(args.host, args.apikey, args.verify_tls),
            args.host)
    elif args.target == "panorama":
        if not (args.host and args.apikey):
            ap.error("--target panorama requires --host and --apikey")
        source = f"Panorama {args.host}"
        print(f"[*] Enumerating devices via Panorama {args.host}")
        devs = list_panorama_devices(args.host, args.apikey, args.verify_tls)
        print(f"    found {len(devs)} connected device(s)")
        for serial, hostname in devs:
            label = f"{hostname} ({serial})"
            print(f"    - pulling config: {label}")
            try:
                cfg = get_device_config_via_panorama(
                    args.host, args.apikey, serial, args.verify_tls)
                all_rows += run_checks(cfg, label)
            except Exception as e:
                all_rows.append({"device": label, "id": "-", "title": "config pull",
                                 "severity": "-", "result": "ERROR",
                                 "evidence": str(e)})
    else:
        ap.error("provide either --offline PATH or --target {panorama,firewall}")

        
    # Load and apply exemptions
    exemptions = load_exemptions()
    if exemptions:
        all_rows = apply_exemptions(all_rows, exemptions)
        print(f"[*] Applied {len(exemptions)} exemptions (N/A)")

    if not all_rows:
        raise SystemExit("No results produced.")

    meta = {"generated": generated, "benchmark": args.benchmark, "source": source}
    csv_p = write_csv(all_rows, args.out, ts)
    html_p = write_html(all_rows, args.out, ts, meta)
    pdf_p = write_pdf(all_rows, args.out, ts, meta)

    s = _summary(all_rows)
    print("\n=== Summary ===")
    print(f"  Devices : {len({r['device'] for r in all_rows})}")
    print(f"  Overall : PASS={s.get('PASS',0)}  FAIL={s.get('FAIL',0)}  "
          f"N/A={s.get('N/A',0)}  ERROR={s.get('ERROR',0)}")
    print("\n  Per device:")
    for device, dev_rows in _group_by_device(all_rows):
        ds = _device_summary(dev_rows)
        parts = "  ".join(f"{k}={v}" for k, v in sorted(ds.items()))
        print(f"    {device:45} {parts}")
    print(f"\nReports:\n  CSV : {csv_p}\n  HTML: {html_p}\n  PDF : {pdf_p}")


if __name__ == "__main__":
    main()
