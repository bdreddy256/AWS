"""
CIS Palo Alto Firewall 11 Benchmark v1.2.0 - ALL 55 CONTROLS.

Remapped to Tenable .audit file: exact control numbers, XPaths, defaults.
Zero external dependencies.

Sections 1,4-5: fully config-based (~27 checks)
Sections 2-3,6-8: REVIEW (policy-based or operational, requires manual verification)
"""

import xml.etree.ElementTree as ET

def _text(root, path):
    rel = path[7:] if path.startswith("config/") else path
    el = root.find(".//" + rel)
    return el.text.strip() if (el is not None and el.text) else None

def _exists(root, path):
    rel = path[7:] if path.startswith("config/") else path
    return root.find(".//" + rel) is not None

def _int(v):
    try: return int(v)
    except: return None

# ===================== SECTION 1: MANAGEMENT HARDENING ====================

def chk_1_1_2_login_banner(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/login-banner")
    if v: return "PASS", "login-banner set"
    return "FAIL", "login-banner not set (default: not configured)"

def chk_1_1_3_log_high_dp_load(root):
    v = _text(root, "config/devices/entry/deviceconfig/setting/management/enable-log-high-dp-load")
    return ("PASS" if v == "yes" else "FAIL"), f"enable-log-high-dp-load={v or 'default: disabled'}"

def chk_1_2_1_permitted_ip(root):
    if _exists(root, "config/devices/entry/deviceconfig/system/permitted-ip/entry"):
        n = len(root.findall("./deviceconfig/system/permitted-ip/entry"))
        return "PASS", f"permitted-ip configured ({n} entries)"
    return "FAIL", "no permitted-ip (default: all addresses permitted)"

def chk_1_2_3_http_telnet_disabled(root):
    http = _text(root, "config/devices/entry/deviceconfig/system/service/disable-http")
    telnet = _text(root, "config/devices/entry/deviceconfig/system/service/disable-telnet")
    http_ok = (http == "yes") or (http is None)
    telnet_ok = (telnet == "yes") or (telnet is None)
    if http_ok and telnet_ok:
        return "PASS", f"disable-http={http or 'default'}, disable-telnet={telnet or 'default'}"
    bad = []
    if not http_ok: bad.append("HTTP enabled")
    if not telnet_ok: bad.append("Telnet enabled")
    return "FAIL", "; ".join(bad)

def _pw_min(root, leaf, minimum, label):
    v = _text(root, f"config/mgt-config/password-complexity/{leaf}")
    if v is None: return "FAIL", f"{label} not set"
    n = _int(v)
    if n is None: return "FAIL", f"{label} unparseable: {v}"
    return ("PASS" if n >= minimum else "FAIL"), f"{label}={v}"

def chk_1_3_1_complexity_enabled(root):
    v = _text(root, "config/mgt-config/password-complexity/enabled")
    return ("PASS" if v == "yes" else "FAIL"), f"enabled={v or 'not set'}"

def chk_1_3_2_min_length(root): return _pw_min(root, "minimum-length", 12, "minimum-length")
def chk_1_3_3_min_upper(root): return _pw_min(root, "minimum-uppercase-letters", 1, "min-upper")
def chk_1_3_4_min_lower(root): return _pw_min(root, "minimum-lowercase-letters", 1, "min-lower")
def chk_1_3_5_min_numeric(root): return _pw_min(root, "minimum-numeric-letters", 1, "min-numeric")
def chk_1_3_6_min_special(root): return _pw_min(root, "minimum-special-characters", 1, "min-special")

def chk_1_3_7_change_period(root):
    v = _text(root, "config/mgt-config/password-complexity/password-change/expiration-period")
    if v is None: return "FAIL", "expiration-period not set"
    n = _int(v)
    return ("PASS" if n and n <= 90 else "FAIL"), f"expiration-period={v} days"

def chk_1_3_8_differs_by(root): return _pw_min(root, "new-password-differs-by-characters", 3, "differs-by")
def chk_1_3_9_reuse_limit(root): return _pw_min(root, "password-history-count", 24, "reuse-limit")

def chk_1_3_10_no_password_profiles(root):
    if _exists(root, "config/mgt-config/password-profile/entry"):
        return "FAIL", "password-profile(s) exist (should not)"
    return "PASS", "no password-profiles"

def chk_1_4_1_idle_timeout(root):
    v = _text(root, "config/devices/entry/deviceconfig/setting/management/idle-timeout")
    if v is None:
        return "FAIL", "idle-timeout not set (default: not configured)"
    n = _int(v)
    if n == 0: return "FAIL", "idle-timeout=0 (never expires)"
    return ("PASS" if n and n <= 10 else "FAIL"), f"idle-timeout={v} min"

def chk_1_5_1_snmp_v3(root):
    if _exists(root, "config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v3"):
        return "PASS", "SNMP v3 selected"
    return "FAIL", "SNMP v3 not selected"

def chk_1_6_1_verify_update_server(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/server-verification")
    if v is None or v == "yes": return "PASS", f"server-verification={v or 'default'}"
    return "FAIL", f"server-verification={v}"

def chk_1_6_2_redundant_ntp(root):
    primary = _text(root, "config/devices/entry/deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address")
    secondary = _text(root, "config/devices/entry/deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address")
    if primary and secondary: return "PASS", "primary+secondary NTP configured"
    if not primary and not secondary: return "FAIL", "no NTP servers"
    return "FAIL", f"incomplete (primary={'y' if primary else 'n'}, secondary={'y' if secondary else 'n'})"

# ===================== SECTION 2: USER-ID ================================

def chk_2_3_userid_trusted_only(root):
    return "REVIEW", "Verify User-ID zones/interfaces - Device > User Identification > User-ID Agent"

def chk_2_4_userid_include_exclude(root):
    return "REVIEW", "Verify Include/Exclude Networks - Device > User Identification > User-ID Agent"

def chk_2_8_userid_no_crosszone(root):
    return "REVIEW", "Verify security policies restrict User-ID Agent traffic - policy audit needed"

# ===================== SECTION 3: HA ======================================

def chk_3_1_ha_synchronized(root):
    return "REVIEW", "Verify HA state via 'show high-availability all' - operational state, not config"

# ===================== SECTION 4: UPDATES ================================

def chk_4_1_av_update_schedule(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/update-schedule/anti-virus/recurring/hourly/action")
    if v == "download-and-install": return "PASS", "AV schedule: download-and-install"
    if v: return "FAIL", f"AV schedule={v} (not download-and-install)"
    return "FAIL", "no AV update schedule"

def chk_4_2_threats_update_schedule(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/update-schedule/threats/recurring/hourly/action")
    if v == "download-and-install": return "PASS", "Threats schedule: download-and-install"
    if v: return "FAIL", f"Threats schedule={v}"
    return "FAIL", "no Threats update schedule"

# ===================== SECTION 5: WILDFIRE ===============================

def chk_5_1_wildfire_file_size(root):
    if _exists(root, "config/devices/entry/deviceconfig/setting/wildfire/file-size-limit/entry"):
        return "PASS", "WildFire file-size-limit configured"
    return "FAIL", "no WildFire file-size-limit"

def chk_5_2_wildfire_analysis_profile(root):
    return "REVIEW", "Policy: WildFire Analysis profile attached to all allow rules"

def chk_5_3_wildfire_decrypted_forward(root):
    v = _text(root, "config/devices/entry/vsys/entry/setting/ssl-decrypt/allow-forward-decrypted-content")
    if v == "yes": return "PASS", "forward decrypted to WildFire: yes"
    return "FAIL", f"allow-forward-decrypted-content={v or 'not set'}"

def chk_5_4_wildfire_session_info(root):
    if _exists(root, "config/devices/entry/vsys/entry/setting/wildfire/session-info-select"):
        v = _text(root, "config/devices/entry/vsys/entry/setting/wildfire/session-info-select/exclude-src-ip")
        if v == "no" or v is None: return "PASS", "session-info enabled"
        return "FAIL", f"exclude-src-ip={v}"
    return "FAIL", "no session-info-select"

def chk_5_5_wildfire_alerts(root):
    if _exists(root, "config/shared/log-settings/profiles/entry"):
        return "PASS", "log-settings profiles configured"
    return "FAIL", "no log-settings profiles"

def chk_5_6_wildfire_update_schedule(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/update-schedule/wildfire/recurring/real-time/action")
    if v == "download-and-install": return "PASS", "WildFire schedule: download-and-install"
    if v: return "FAIL", f"WildFire schedule={v}"
    return "FAIL", "no WildFire update schedule"

def chk_5_8_wildfire_cloud_analysis(root):
    if _exists(root, "config/devices/entry/device-group/entry/profiles/wildfire-analysis/entry"):
        v = _text(root, "config/devices/entry/device-group/entry/profiles/wildfire-analysis/entry/mica-engine-wildfire-rules/cloud-inline-analysis")
        if v == "yes": return "PASS", "Cloud Analysis enabled"
        return "FAIL", f"cloud-inline-analysis={v}"
    if _exists(root, "config/shared/profiles/wildfire-analysis/entry"):
        v = _text(root, "config/shared/profiles/wildfire-analysis/entry/mica-engine-wildfire-rules/cloud-inline-analysis")
        if v == "yes": return "PASS", "Cloud Analysis enabled"
        return "FAIL", f"cloud-inline-analysis={v}"
    return "FAIL", "no WildFire profile"

# ===================== SECTION 6: SECURITY PROFILES =======================

def chk_6_1_av_reset_both(root): return "REVIEW", "Policy: AV profiles set to reset-both on all decoders"
def chk_6_2_av_profile_on_rules(root): return "REVIEW", "Policy: AV profile attached to all relevant rules"
def chk_6_3_anti_spyware_block(root): return "REVIEW", "Policy: Anti-spyware blocks all spyware severity levels"
def chk_6_5_spyware_profile_on_rules(root): return "REVIEW", "Policy: Anti-spyware profile attached to all rules"
def chk_6_6_vulnerability_block(root): return "REVIEW", "Policy: Vuln Profile blocks attacks vs critical vulns"
def chk_6_7_vuln_profile_on_rules(root): return "REVIEW", "Policy: Vuln Profile attached to all rules"
def chk_6_8_pandb_url_filter(root): return "REVIEW", "Policy: PAN-DB URL Filtering used in URL profiles"
def chk_6_9_url_filter_block(root): return "REVIEW", "Policy: URL Filter uses block/override on dangerous cats"
def chk_6_10_url_logging(root): return "REVIEW", "Policy: logging enabled for every URL Filter access"
def chk_6_12_secure_url_filter(root): return "REVIEW", "Policy: Secure URL filtering for all web policies"
def chk_6_14_data_filter_profile(root): return "REVIEW", "Policy: Data Filter profile attached to all rules"
def chk_6_15_zone_protection_syn(root): return "REVIEW", "Policy: Zone Protection with SYN Flood action"
def chk_6_17_zone_protection_recon(root): return "REVIEW", "Policy: All zones have Zone Protection recon rules"
def chk_6_18_zone_protection_malformed(root): return "REVIEW", "Policy: All zones drop malformed packets"
def chk_6_19_credential_block(root): return "REVIEW", "Policy: Credential submission action block/override"
def chk_6_20_wildfire_ml_av(root): return "REVIEW", "Policy: WildFire ML on AV: block-malicious"
def chk_6_21_wildfire_ml_enabled(root): return "REVIEW", "Policy: WildFire ML enabled on AV profiles"
def chk_6_22_cloud_analysis_vuln(root): return "REVIEW", "Policy: Cloud Analysis enabled on Vuln profiles"
def chk_6_23_cloud_categorization_url(root): return "REVIEW", "Policy: Cloud Categorization enabled on URL profiles"
def chk_6_24_cloud_analysis_spyware(root): return "REVIEW", "Policy: Cloud Analysis enabled on Anti-Spyware"

# ===================== SECTION 7: POLICY HYGIENE ==========================

def chk_7_2_no_service_any(root): return "REVIEW", "Policy: No 'Service ANY' in allow policies"
def chk_7_3_implicit_deny(root): return "REVIEW", "Policy: Implicit deny rule exists"
def chk_7_4_builtin_logging(root): return "REVIEW", "Policy: Logging enabled on built-in default policies"

# ===================== SECTION 8: DECRYPTION =============================

def chk_8_2_ssl_inbound(root): return "REVIEW", "Policy: SSL Inbound Inspection for untrusted traffic"

# ===================== CHECK REGISTRY ====================================

CHECKS = [
    {"id": "1.1.2", "title": "Login Banner set", "severity": "Low", "fn": chk_1_1_2_login_banner},
    {"id": "1.1.3", "title": "High DP Load logging", "severity": "Low", "fn": chk_1_1_3_log_high_dp_load},
    {"id": "1.2.1", "title": "Permitted IP for mgmt", "severity": "High", "fn": chk_1_2_1_permitted_ip},
    {"id": "1.2.3", "title": "HTTP/Telnet disabled", "severity": "High", "fn": chk_1_2_3_http_telnet_disabled},
    {"id": "1.3.1", "title": "Password Complexity", "severity": "High", "fn": chk_1_3_1_complexity_enabled},
    {"id": "1.3.2", "title": "Min Length >= 12", "severity": "High", "fn": chk_1_3_2_min_length},
    {"id": "1.3.3", "title": "Min Uppercase >= 1", "severity": "Medium", "fn": chk_1_3_3_min_upper},
    {"id": "1.3.4", "title": "Min Lowercase >= 1", "severity": "Medium", "fn": chk_1_3_4_min_lower},
    {"id": "1.3.5", "title": "Min Numeric >= 1", "severity": "Medium", "fn": chk_1_3_5_min_numeric},
    {"id": "1.3.6", "title": "Min Special >= 1", "severity": "Medium", "fn": chk_1_3_6_min_special},
    {"id": "1.3.7", "title": "Change Period <= 90d", "severity": "Medium", "fn": chk_1_3_7_change_period},
    {"id": "1.3.8", "title": "Differs By >= 3", "severity": "Medium", "fn": chk_1_3_8_differs_by},
    {"id": "1.3.9", "title": "Reuse Limit >= 24", "severity": "Medium", "fn": chk_1_3_9_reuse_limit},
    {"id": "1.3.10", "title": "No Password Profiles", "severity": "Medium", "fn": chk_1_3_10_no_password_profiles},
    {"id": "1.4.1", "title": "Idle Timeout <= 10m", "severity": "Medium", "fn": chk_1_4_1_idle_timeout},
    {"id": "1.5.1", "title": "SNMP v3 selected", "severity": "Medium", "fn": chk_1_5_1_snmp_v3},
    {"id": "1.6.1", "title": "Verify Update Server", "severity": "Medium", "fn": chk_1_6_1_verify_update_server},
    {"id": "1.6.2", "title": "Redundant NTP", "severity": "Low", "fn": chk_1_6_2_redundant_ntp},
    {"id": "2.3", "title": "User-ID trusted only", "severity": "Medium", "fn": chk_2_3_userid_trusted_only},
    {"id": "2.4", "title": "User-ID Include/Exclude", "severity": "Medium", "fn": chk_2_4_userid_include_exclude},
    {"id": "2.8", "title": "User-ID cross-zone", "severity": "Medium", "fn": chk_2_8_userid_no_crosszone},
    {"id": "3.1", "title": "HA synchronized", "severity": "Medium", "fn": chk_3_1_ha_synchronized},
    {"id": "4.1", "title": "AV Update Schedule", "severity": "Medium", "fn": chk_4_1_av_update_schedule},
    {"id": "4.2", "title": "Threats Update Schedule", "severity": "Medium", "fn": chk_4_2_threats_update_schedule},
    {"id": "5.1", "title": "WildFire file size", "severity": "Medium", "fn": chk_5_1_wildfire_file_size},
    {"id": "5.2", "title": "WildFire Analysis rules", "severity": "High", "fn": chk_5_2_wildfire_analysis_profile},
    {"id": "5.3", "title": "WildFire forward decrypted", "severity": "Medium", "fn": chk_5_3_wildfire_decrypted_forward},
    {"id": "5.4", "title": "WildFire session info", "severity": "Medium", "fn": chk_5_4_wildfire_session_info},
    {"id": "5.5", "title": "WildFire alerts", "severity": "Medium", "fn": chk_5_5_wildfire_alerts},
    {"id": "5.6", "title": "WildFire Update Schedule", "severity": "Medium", "fn": chk_5_6_wildfire_update_schedule},
    {"id": "5.8", "title": "WildFire Cloud Analysis", "severity": "Medium", "fn": chk_5_8_wildfire_cloud_analysis},
    {"id": "6.1", "title": "AV reset-both", "severity": "High", "fn": chk_6_1_av_reset_both},
    {"id": "6.2", "title": "AV profile on rules", "severity": "High", "fn": chk_6_2_av_profile_on_rules},
    {"id": "6.3", "title": "Anti-spyware block", "severity": "High", "fn": chk_6_3_anti_spyware_block},
    {"id": "6.5", "title": "Anti-spyware profile", "severity": "High", "fn": chk_6_5_spyware_profile_on_rules},
    {"id": "6.6", "title": "Vuln block attacks", "severity": "High", "fn": chk_6_6_vulnerability_block},
    {"id": "6.7", "title": "Vuln profile on rules", "severity": "High", "fn": chk_6_7_vuln_profile_on_rules},
    {"id": "6.8", "title": "PAN-DB URL Filter", "severity": "Medium", "fn": chk_6_8_pandb_url_filter},
    {"id": "6.9", "title": "URL Filter block", "severity": "Medium", "fn": chk_6_9_url_filter_block},
    {"id": "6.10", "title": "URL logging", "severity": "Medium", "fn": chk_6_10_url_logging},
    {"id": "6.12", "title": "Secure URL Filter", "severity": "Medium", "fn": chk_6_12_secure_url_filter},
    {"id": "6.14", "title": "Data Filter profile", "severity": "Medium", "fn": chk_6_14_data_filter_profile},
    {"id": "6.15", "title": "Zone Protection SYN", "severity": "Medium", "fn": chk_6_15_zone_protection_syn},
    {"id": "6.17", "title": "Zone Protection recon", "severity": "Medium", "fn": chk_6_17_zone_protection_recon},
    {"id": "6.18", "title": "Zone Protection malformed", "severity": "Medium", "fn": chk_6_18_zone_protection_malformed},
    {"id": "6.19", "title": "Credential block", "severity": "Medium", "fn": chk_6_19_credential_block},
    {"id": "6.20", "title": "WildFire ML block", "severity": "Medium", "fn": chk_6_20_wildfire_ml_av},
    {"id": "6.21", "title": "WildFire ML enabled", "severity": "Medium", "fn": chk_6_21_wildfire_ml_enabled},
    {"id": "6.22", "title": "Cloud Analysis Vuln", "severity": "Medium", "fn": chk_6_22_cloud_analysis_vuln},
    {"id": "6.23", "title": "Cloud Categorization URL", "severity": "Medium", "fn": chk_6_23_cloud_categorization_url},
    {"id": "6.24", "title": "Cloud Analysis Spyware", "severity": "Medium", "fn": chk_6_24_cloud_analysis_spyware},
    {"id": "7.2", "title": "No Service ANY", "severity": "Medium", "fn": chk_7_2_no_service_any},
    {"id": "7.3", "title": "Implicit deny", "severity": "Medium", "fn": chk_7_3_implicit_deny},
    {"id": "7.4", "title": "Builtin logging", "severity": "Medium", "fn": chk_7_4_builtin_logging},
    {"id": "8.2", "title": "SSL Inbound Inspection", "severity": "High", "fn": chk_8_2_ssl_inbound},
]

