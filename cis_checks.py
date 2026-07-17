"""
CIS Palo Alto Firewall 11 Benchmark v1.2.0 (Level 1) - config checks.

REMAPPED to match the official Tenable .audit file: correct control numbers,
exact XPaths, and documented default values / default results.

Zero external dependencies - xml.etree.ElementTree only.
Each check returns (result, evidence) where result in {PASS, FAIL, MANUAL, REVIEW}.

SCOPE: Implements Section 1 (device management-plane hardening) in full - the
controls cleanly evaluable from merged config. Sections 2-8 (User-ID, HA, content
updates, WildFire, security profiles applied to policies, policy hygiene,
decryption) are POLICY-based: they require evaluating every security rule and
profile attachment. They are listed as REVIEW placeholders so the report shows
them as not-yet-automated rather than silently omitting them.

PATHS: the .audit XPaths are absolute (config/devices/entry/...). Against the
merged config this tool pulls, root is <config>, so we query with a leading
".//" to match regardless of devices/entry/template nesting - matching how the
values actually appear in merged config.

DEFAULTS: taken from the .audit "Default Value" field; the CIS pass/fail on an
absent setting is encoded so "absent" yields the same verdict Tenable reports.
"""

import xml.etree.ElementTree as ET


def _text(root, path):
    rel = path[len("config/"):] if path.startswith("config/") else path
    el = root.find(".//" + rel)
    return el.text.strip() if (el is not None and el.text) else None


def _exists(root, path):
    rel = path[len("config/"):] if path.startswith("config/") else path
    return root.find(".//" + rel) is not None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---- Section 1.1 : General management -------------------------------------

def chk_1_1_2_login_banner(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/login-banner")
    if v:
        return "PASS", "login-banner set"
    return "FAIL", "login-banner not set (default: not configured)"


def chk_1_1_3_log_high_dp_load(root):
    v = _text(root, "config/devices/entry/deviceconfig/setting/management/enable-log-high-dp-load")
    return ("PASS" if v == "yes" else "FAIL"), f"enable-log-high-dp-load={v or 'not set (default: disabled)'}"


# ---- Section 1.2 : Management interface -----------------------------------

def chk_1_2_1_permitted_ip(root):
    if _exists(root, "config/devices/entry/deviceconfig/system/permitted-ip/entry"):
        n = 0
        for pi in root.iter("permitted-ip"):
            n += len([e for e in pi.findall("entry") if e.get("name")])
        return "PASS", f"permitted-ip configured ({n} entr(y/ies))"
    return "FAIL", "no permitted-ip (default: all addresses permitted)"


def chk_1_2_3_http_telnet_disabled(root):
    http = _text(root, "config/devices/entry/deviceconfig/system/service/disable-http")
    telnet = _text(root, "config/devices/entry/deviceconfig/system/service/disable-telnet")
    # default: HTTP and Telnet disabled by default (absent = disabled = PASS)
    http_ok = (http == "yes") or (http is None)
    telnet_ok = (telnet == "yes") or (telnet is None)
    if http_ok and telnet_ok:
        return "PASS", f"disable-http={http or 'default-disabled'}, disable-telnet={telnet or 'default-disabled'}"
    bad = []
    if not http_ok:
        bad.append("HTTP enabled")
    if not telnet_ok:
        bad.append("Telnet enabled")
    return "FAIL", "; ".join(bad)


# ---- Section 1.3 : Password complexity ------------------------------------

def _pw_min(root, leaf, minimum, label):
    v = _text(root, f"config/mgt-config/password-complexity/{leaf}")
    if v is None:
        return "FAIL", f"{label} not set (default: complexity disabled)"
    n = _int(v)
    if n is None:
        return "FAIL", f"{label} unparseable: {v!r}"
    return ("PASS" if n >= minimum else "FAIL"), f"{label}={v}"


def chk_1_3_1_complexity_enabled(root):
    v = _text(root, "config/mgt-config/password-complexity/enabled")
    return ("PASS" if v == "yes" else "FAIL"), f"password-complexity enabled={v or 'not set'}"


def chk_1_3_2_min_length(root):
    return _pw_min(root, "minimum-length", 12, "minimum-length")


def chk_1_3_3_min_upper(root):
    return _pw_min(root, "minimum-uppercase-letters", 1, "minimum-uppercase-letters")


def chk_1_3_4_min_lower(root):
    return _pw_min(root, "minimum-lowercase-letters", 1, "minimum-lowercase-letters")


def chk_1_3_5_min_numeric(root):
    return _pw_min(root, "minimum-numeric-letters", 1, "minimum-numeric-letters")


def chk_1_3_6_min_special(root):
    return _pw_min(root, "minimum-special-characters", 1, "minimum-special-characters")


def chk_1_3_7_change_period(root):
    v = _text(root, "config/mgt-config/password-complexity/password-change/expiration-period")
    if v is None:
        return "FAIL", "expiration-period not set (default: disabled)"
    n = _int(v)
    if n is None:
        return "FAIL", f"expiration-period unparseable: {v!r}"
    return ("PASS" if n <= 90 else "FAIL"), f"expiration-period={v} days"


def chk_1_3_8_differs_by(root):
    return _pw_min(root, "new-password-differs-by-characters", 3, "new-password-differs-by-characters")


def chk_1_3_9_reuse_limit(root):
    return _pw_min(root, "password-history-count", 24, "password-history-count")


def chk_1_3_10_no_password_profiles(root):
    if _exists(root, "config/mgt-config/password-profile/entry"):
        return "FAIL", "password-profile(s) exist (should not)"
    return "PASS", "no password-profiles (default)"


# ---- Section 1.4 : Idle timeout -------------------------------------------

def chk_1_4_1_idle_timeout(root):
    v = _text(root, "config/devices/entry/deviceconfig/setting/management/idle-timeout")
    if v is None:
        return "FAIL", ("global mgmt idle-timeout not set (default: not configured). "
                        "NOTE: may be enforced via an authentication profile instead - verify manually")
    n = _int(v)
    if n is None:
        return "FAIL", f"idle-timeout unparseable: {v!r}"
    if n == 0:
        return "FAIL", "idle-timeout=0 (never expires)"
    return ("PASS" if n <= 10 else "FAIL"), f"idle-timeout={v} min"


# ---- Section 1.5 : SNMP ----------------------------------------------------

def chk_1_5_1_snmp_v3(root):
    if _exists(root, "config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v3"):
        return "PASS", "SNMP v3 selected"
    return "FAIL", "SNMP v3 not selected (default: not configured)"


# ---- Section 1.6 : Update server / NTP ------------------------------------

def chk_1_6_1_verify_update_server(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/server-verification")
    if v is None or v == "yes":
        return "PASS", f"server-verification={v or 'default (verifies)'}"
    return "FAIL", f"server-verification={v}"


def chk_1_6_2_redundant_ntp(root):
    primary = _text(root, "config/devices/entry/deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address")
    secondary = _text(root, "config/devices/entry/deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address")
    if primary and secondary:
        return "PASS", "primary+secondary NTP configured"
    if not primary and not secondary:
        return "FAIL", "no NTP servers configured"
    return "FAIL", f"redundant NTP incomplete (primary={'y' if primary else 'n'}, secondary={'y' if secondary else 'n'})"


# ---- Policy-based (Sections 2-8): REVIEW placeholders ----------------------

def _review(msg):
    def _f(root):
        return "REVIEW", msg
    return _f


CHECKS = [
    {"id": "1.1.2", "title": "Login Banner is set",
     "severity": "Low", "fn": chk_1_1_2_login_banner},
    {"id": "1.1.3", "title": "Enable Log on High DP Load is enabled",
     "severity": "Low", "fn": chk_1_1_3_log_high_dp_load},
    {"id": "1.2.1", "title": "Permitted IP Addresses set for mgmt",
     "severity": "High", "fn": chk_1_2_1_permitted_ip},
    {"id": "1.2.3", "title": "HTTP and Telnet disabled on mgmt interface",
     "severity": "High", "fn": chk_1_2_3_http_telnet_disabled},
    {"id": "1.3.1", "title": "Minimum Password Complexity enabled",
     "severity": "High", "fn": chk_1_3_1_complexity_enabled},
    {"id": "1.3.2", "title": "Minimum Length >= 12",
     "severity": "High", "fn": chk_1_3_2_min_length},
    {"id": "1.3.3", "title": "Minimum Uppercase Letters >= 1",
     "severity": "Medium", "fn": chk_1_3_3_min_upper},
    {"id": "1.3.4", "title": "Minimum Lowercase Letters >= 1",
     "severity": "Medium", "fn": chk_1_3_4_min_lower},
    {"id": "1.3.5", "title": "Minimum Numeric Letters >= 1",
     "severity": "Medium", "fn": chk_1_3_5_min_numeric},
    {"id": "1.3.6", "title": "Minimum Special Characters >= 1",
     "severity": "Medium", "fn": chk_1_3_6_min_special},
    {"id": "1.3.7", "title": "Required Password Change Period <= 90 days",
     "severity": "Medium", "fn": chk_1_3_7_change_period},
    {"id": "1.3.8", "title": "New Password Differs By Characters >= 3",
     "severity": "Medium", "fn": chk_1_3_8_differs_by},
    {"id": "1.3.9", "title": "Prevent Password Reuse Limit >= 24",
     "severity": "Medium", "fn": chk_1_3_9_reuse_limit},
    {"id": "1.3.10", "title": "Password Profiles do not exist",
     "severity": "Medium", "fn": chk_1_3_10_no_password_profiles},
    {"id": "1.4.1", "title": "Idle timeout <= 10 minutes",
     "severity": "Medium", "fn": chk_1_4_1_idle_timeout},
    {"id": "1.5.1", "title": "SNMP v3 selected for polling",
     "severity": "Medium", "fn": chk_1_5_1_snmp_v3},
    {"id": "1.6.1", "title": "Verify Update Server Identity enabled",
     "severity": "Medium", "fn": chk_1_6_1_verify_update_server},
    {"id": "1.6.2", "title": "Redundant NTP servers configured",
     "severity": "Low", "fn": chk_1_6_2_redundant_ntp},

    {"id": "2.3", "title": "User-ID only on internal trusted interfaces",
     "severity": "Medium", "fn": _review("Policy-based: verify User-ID zone/interface assignment manually")},
    {"id": "3.1", "title": "Fully-synchronized HA peer configured",
     "severity": "Medium", "fn": _review("Verify HA state via 'show high-availability all' - not config-only")},
    {"id": "4.1", "title": "Antivirus Update Schedule download+install",
     "severity": "Medium", "fn": _review("Verify update-schedule/threats - automatable next phase")},
    {"id": "4.2", "title": "Apps & Threats Update Schedule download+install",
     "severity": "Medium", "fn": _review("Verify update-schedule - automatable next phase")},
    {"id": "5.6", "title": "WildFire Update Schedule download+install",
     "severity": "Medium", "fn": _review("Verify update-schedule/wildfire - automatable next phase")},
    {"id": "6.x", "title": "Security profiles applied to all policies (AV/AS/VP/URL)",
     "severity": "High", "fn": _review("Policy-based: requires per-rule profile-attachment evaluation")},
    {"id": "7.2", "title": "No 'Service ANY' in allow policies",
     "severity": "Medium", "fn": _review("Policy-based: iterate security rules - next phase")},
    {"id": "7.4", "title": "Logging enabled on default security policies",
     "severity": "Medium", "fn": _review("Policy-based: check rulebase logging - next phase")},
    {"id": "8.2", "title": "SSL Inbound Inspection for untrusted traffic",
     "severity": "High", "fn": _review("Policy-based: decryption rule evaluation - next phase")},
]
