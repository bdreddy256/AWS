"""
CIS Palo Alto Firewall Benchmark checks for PAN-OS.

ZERO EXTERNAL DEPENDENCIES — uses only Python's standard-library
xml.etree.ElementTree. No lxml, no pip install required.

Each check evaluates the firewall RUNNING config XML. When run against a live
firewall the running config already contains the merged/effective values
(local + Panorama-pushed), so element paths against it are authoritative.

Every check returns (result, evidence) where result in {PASS, FAIL, MANUAL}.

STARTER SET: ~14 high-value automatable controls + procedural placeholders.
The full CIS PAN-OS benchmark has ~150+ controls. Validate each check's logic
and path against your CIS PDF and PAN-OS version before relying on output as
audit evidence.

NOTE ON PATHS: ElementTree supports a limited path subset (.//tag/child). It does
NOT support attribute predicates in findall, so where we need attributes we
iterate and read .get()/.text in Python.
"""


def _findtext(root, path):
    """Return stripped text at path, or None."""
    el = root.find(path)
    if el is None or el.text is None:
        return None
    return el.text.strip()


def _exists(root, path):
    return root.find(path) is not None


# --- Checks ---

def chk_minimum_password_length(root):
    val = _findtext(root, ".//mgt-config/password-complexity/minimum-length")
    if val is None:
        return "FAIL", "minimum-length not configured (complexity likely disabled)"
    try:
        return ("PASS" if int(val) >= 12 else "FAIL"), f"minimum-length={val}"
    except ValueError:
        return "FAIL", f"minimum-length unparseable: {val!r}"


def chk_password_complexity_enabled(root):
    val = _findtext(root, ".//mgt-config/password-complexity/enabled")
    return ("PASS" if val == "yes" else "FAIL"), f"password-complexity enabled={val or 'unset'}"


def chk_idle_timeout(root):
    val = _findtext(root, ".//deviceconfig/setting/management/idle-timeout")
    if val is None:
        return "FAIL", "idle-timeout not set (default may be too high)"
    try:
        return ("PASS" if 0 < int(val) <= 10 else "FAIL"), f"idle-timeout={val} min"
    except ValueError:
        return "FAIL", f"idle-timeout unparseable: {val!r}"


def chk_failed_login_lockout(root):
    val = _findtext(root, ".//mgt-config/authentication/failed-attempts")
    if val is None:
        return "FAIL", "failed-attempts lockout not configured"
    try:
        return ("PASS" if 1 <= int(val) <= 5 else "FAIL"), f"failed-attempts={val}"
    except ValueError:
        return "FAIL", f"failed-attempts unparseable: {val!r}"


def chk_lockout_time(root):
    val = _findtext(root, ".//mgt-config/authentication/lockout-time")
    if val is None:
        return "FAIL", "lockout-time not configured"
    try:
        return ("PASS" if int(val) >= 15 else "FAIL"), f"lockout-time={val} min"
    except ValueError:
        return "FAIL", f"lockout-time unparseable: {val!r}"


def chk_mgmt_permitted_ips(root):
    # permitted-ip/entry has the IP in the 'name' attribute
    entries = []
    for pi in root.iter("permitted-ip"):
        for entry in pi.findall("entry"):
            name = entry.get("name")
            if name:
                entries.append(name)
    if entries:
        return "PASS", f"permitted-ip restricted to {len(entries)} entr(y/ies)"
    return "FAIL", "no permitted-ip set — mgmt reachable from any source"


def chk_http_disabled(root):
    val = _findtext(root, ".//deviceconfig/system/service/disable-http")
    return ("PASS" if val == "yes" else "FAIL"), f"disable-http={val or 'no'}"


def chk_telnet_disabled(root):
    val = _findtext(root, ".//deviceconfig/system/service/disable-telnet")
    return ("PASS" if val == "yes" else "FAIL"), f"disable-telnet={val or 'no'}"


def chk_snmpv2_not_used(root):
    has_v2 = any(True for _ in root.iter("v2c"))
    has_v3 = any(True for _ in root.iter("v3"))
    # only treat as SNMP if under an snmp-setting subtree
    snmp_present = any(True for _ in root.iter("snmp-setting"))
    if has_v2:
        return "FAIL", "SNMP v2c configured — use v3"
    if has_v3:
        return "PASS", "SNMP v3 in use"
    if snmp_present:
        return "MANUAL", "SNMP configured but version unclear — verify v3"
    return "MANUAL", "no SNMP config found — confirm SNMP intentionally disabled"


def chk_login_banner(root):
    val = _findtext(root, ".//deviceconfig/system/login-banner")
    return ("PASS" if val else "FAIL"), ("login-banner set" if val else "no login-banner")


def chk_ntp_configured(root):
    val = _findtext(root,
        ".//deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address")
    return ("PASS" if val else "FAIL"), (f"NTP primary={val}" if val else "no NTP server")


def chk_min_tls_version(root):
    versions = [el.text.strip() for el in root.iter("min-version")
                if el.text and el.text.strip()]
    if not versions:
        return "MANUAL", "no SSL/TLS service profile min-version found — verify mgmt/GP TLS"
    bad = [v for v in versions if v not in ("tls1-2", "tls1-3")]
    if bad:
        return "FAIL", f"min TLS version(s) below 1.2: {sorted(set(bad))}"
    return "PASS", f"all TLS profiles min-version tls1-2+ ({len(versions)} profile(s))"


def chk_log_forwarding_exists(root):
    names = []
    for ls in root.iter("log-settings"):
        for prof in ls.iter("profiles"):
            for entry in prof.findall("entry"):
                if entry.get("name"):
                    names.append(entry.get("name"))
    if names:
        return "PASS", f"{len(names)} log-forwarding profile(s) defined"
    return "FAIL", "no log-forwarding profiles — logs may not be centralized"


def chk_wildfire_updates(root):
    present = any(True for _ in root.iter("wildfire"))
    return ("PASS" if present else "MANUAL"), (
        "WildFire update schedule present" if present
        else "confirm WildFire update schedule")


def chk_manual(msg):
    def _f(root):
        return "MANUAL", msg
    return _f


CHECKS = [
    {"id": "CIS-1.1.1", "title": "Minimum password length >= 12",
     "severity": "High", "fn": chk_minimum_password_length},
    {"id": "CIS-1.1.2", "title": "Password complexity enabled",
     "severity": "High", "fn": chk_password_complexity_enabled},
    {"id": "CIS-1.2.1", "title": "Idle timeout <= 10 minutes",
     "severity": "Medium", "fn": chk_idle_timeout},
    {"id": "CIS-1.3.1", "title": "Failed login lockout (1-5 attempts)",
     "severity": "High", "fn": chk_failed_login_lockout},
    {"id": "CIS-1.3.2", "title": "Lockout time >= 15 minutes",
     "severity": "Medium", "fn": chk_lockout_time},
    {"id": "CIS-2.1.1", "title": "Mgmt access restricted by permitted-ip",
     "severity": "High", "fn": chk_mgmt_permitted_ips},
    {"id": "CIS-2.1.2", "title": "HTTP mgmt disabled",
     "severity": "High", "fn": chk_http_disabled},
    {"id": "CIS-2.1.3", "title": "Telnet mgmt disabled",
     "severity": "High", "fn": chk_telnet_disabled},
    {"id": "CIS-2.2.1", "title": "SNMP v2c not in use (v3 preferred)",
     "severity": "Medium", "fn": chk_snmpv2_not_used},
    {"id": "CIS-2.3.1", "title": "Login banner configured",
     "severity": "Low", "fn": chk_login_banner},
    {"id": "CIS-2.4.1", "title": "NTP server configured",
     "severity": "Medium", "fn": chk_ntp_configured},
    {"id": "CIS-2.5.1", "title": "Minimum TLS version tls1-2+",
     "severity": "High", "fn": chk_min_tls_version},
    {"id": "CIS-6.1.1", "title": "Log-forwarding profiles defined",
     "severity": "Medium", "fn": chk_log_forwarding_exists},
    {"id": "CIS-7.1.1", "title": "WildFire dynamic updates scheduled",
     "severity": "Medium", "fn": chk_wildfire_updates},
    {"id": "CIS-8.1.1", "title": "Annual config review performed & signed off",
     "severity": "Medium", "fn": chk_manual(
         "Procedural: evidence via management sign-off, not scannable")},
    {"id": "CIS-8.1.2", "title": "Admin roles follow least privilege (review)",
     "severity": "Medium", "fn": chk_manual(
         "Procedural: validate admin role assignments manually")},
]
