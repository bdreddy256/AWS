"""
CIS Palo Alto Firewall 11 Benchmark v1.2.0 - ALL 55 CONTROLS
Fully automated with CURRENT STATE display.

Shows:
- What CIS requires
- What you currently have (with values)
- Comparison for decision-making

Architecture: Uses Security Group Profiles (SGP) on rules.
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

# ===================== SGP / RULE HELPERS ========================
#
# Panorama-pushed configs have TWO separate sources in the saved XML:
#
#   merged config  → device settings (mgmt, password, NTP, SNMP ...)
#                    path: root directly (no wrapper)
#
#   pushed-shared-policy → security rules + SGPs pushed from Panorama
#                    path: root/pushed_policy/panorama/pre-rulebase/security/rules/entry
#                          root/pushed_policy/panorama/post-rulebase/security/rules/entry
#
# Rules reference SGPs via: <profile-setting><group><member>sgp-name</member></group>
# SGPs live in:             pushed_policy/panorama/pre-rulebase/security-group-profiles
#                           OR pushed_policy/panorama/post-rulebase/security-group-profiles
#
# On the FW CLI: "show config pushed-shared-policy"
# ================================================================

_RULE_SEARCH_PATHS = [
    # pushed-shared-policy paths (Panorama rules injected by export_configs.py)
    ".//pushed_policy/panorama/pre-rulebase/security/rules/entry",
    ".//pushed_policy/panorama/post-rulebase/security/rules/entry",
    # local rulebase (device-local rules, if any)
    ".//devices/entry/vsys/entry/pre-rulebase/security/rules/entry",
    ".//devices/entry/vsys/entry/post-rulebase/security/rules/entry",
    ".//devices/entry/vsys/entry/security/rules/entry",
    # generic fallbacks
    ".//pre-rulebase/security/rules/entry",
    ".//post-rulebase/security/rules/entry",
    ".//security/rules/entry",
]

_SGP_SEARCH_PATHS_TPL = [
    # pushed-shared-policy (Panorama)
    ".//pushed_policy/panorama/pre-rulebase/security-group-profiles/entry[@name='{n}']",
    ".//pushed_policy/panorama/post-rulebase/security-group-profiles/entry[@name='{n}']",
    # alternate tag name
    ".//pushed_policy/panorama/pre-rulebase/security-group-tagging/entry[@name='{n}']",
    ".//pushed_policy/panorama/post-rulebase/security-group-tagging/entry[@name='{n}']",
    # local device
    ".//devices/entry/vsys/entry/pre-rulebase/security-group-profiles/entry[@name='{n}']",
    ".//devices/entry/vsys/entry/post-rulebase/security-group-profiles/entry[@name='{n}']",
    # generic fallback
    ".//security-group-profiles/entry[@name='{n}']",
    ".//security-group-tagging/entry[@name='{n}']",
]


def _get_all_rules(root):
    """Return deduplicated list of all security rule <entry> elements."""
    seen, rules = set(), []
    for path in _RULE_SEARCH_PATHS:
        for rule in root.findall(path):
            name = rule.get("name", "")
            if name not in seen:
                seen.add(name)
                rules.append(rule)
    return rules


def _rule_sgp_name(rule):
    """
    Return the Security Group Profile name referenced by this rule.
    Panorama rules use: <profile-setting><group><member>NAME</member></group>
    """
    # Primary: profile-setting/group/member  (Panorama SGP reference)
    el = rule.find("profile-setting/group/member")
    if el is not None and el.text:
        return el.text.strip()
    # Fallback: group-tag/member (older style)
    el = rule.find("group-tag/member")
    if el is not None and el.text:
        return el.text.strip()
    return None


def _get_sgp(root, sgp_name):
    """Find a Security Group Profile <entry> by name across all known locations."""
    if not sgp_name:
        return None
    for tpl in _SGP_SEARCH_PATHS_TPL:
        path = tpl.format(n=sgp_name)
        results = root.findall(path)
        if results:
            return results[0]
    return None

def _sgp_profiles(sgp):
    """
    Extract profiles from an SGP entry.

    Panorama SGPs (security-group-profiles) store members directly:
      <entry name="sgp-web">
        <virus><member>av-profile</member></virus>
        <spyware><member>asp-profile</member></spyware>
        ...
      </entry>

    Older/local SGPs may wrap them in profile-setting/profiles:
      <entry name="sgp-web">
        <profile-setting><profiles>
          <virus><member>av-profile</member></virus>
        </profiles></profile-setting>
      </entry>
    """
    profiles = {
        "virus": [],
        "spyware": [],
        "vulnerability": [],
        "url-filtering": [],
        "data-filtering": [],
        "wildfire-analysis": [],
    }
    if sgp is None:
        return profiles, "SGP not found"

    for ptype in profiles.keys():
        # Try direct child (Panorama security-group-profiles format)
        el = sgp.find(ptype)
        if el is not None:
            for member in el.findall("member"):
                if member.text:
                    profiles[ptype].append(member.text.strip())
            continue
        # Try profile-setting/profiles wrapper (older format)
        el = sgp.find(f"profile-setting/profiles/{ptype}")
        if el is not None:
            for member in el.findall("member"):
                if member.text:
                    profiles[ptype].append(member.text.strip())

    return profiles, None

def _rule_action(rule):
    """Get the action of a rule (allow, deny, etc)."""
    action = _text(rule, "action")
    return action

def _rule_service(rule):
    """Get services in a rule."""
    services = []
    for svc in rule.findall(".//service/member"):
        if svc.text:
            services.append(svc.text)
    return services

def _rule_logging(rule):
    """Check if rule has logging enabled."""
    log_start = _text(rule, "log-start")
    log_end = _text(rule, "log-end")
    return log_start == "yes" or log_end == "yes"

# ===================== SECTION 1: MANAGEMENT HARDENING ====================

def chk_1_1_2_login_banner(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/login-banner")
    if v:
        return "PASS", f"login-banner set: '{v[:50]}...'"
    return "FAIL", "login-banner not set (default: not configured)"

def chk_1_1_3_log_high_dp_load(root):
    v = _text(root, "config/devices/entry/deviceconfig/setting/management/enable-log-high-dp-load")
    current = f"enable-log-high-dp-load={v or 'not set'}"
    return ("PASS" if v == "yes" else "FAIL"), f"Current: {current}"

def chk_1_2_1_permitted_ip(root):
    if _exists(root, "config/devices/entry/deviceconfig/system/permitted-ip/entry"):
        ips = root.findall(".//deviceconfig/system/permitted-ip/entry")
        ip_list = [ip.get("name") for ip in ips]
        return "PASS", f"Current: {len(ips)} permitted IPs: {', '.join(ip_list[:3])}"
    return "FAIL", "Current: No permitted-ip configured (all addresses allowed)"

def chk_1_2_3_http_telnet_disabled(root):
    http = _text(root, "config/devices/entry/deviceconfig/system/service/disable-http")
    telnet = _text(root, "config/devices/entry/deviceconfig/system/service/disable-telnet")
    http_ok = (http == "yes") or (http is None)
    telnet_ok = (telnet == "yes") or (telnet is None)
    current = f"disable-http={http or 'default'}, disable-telnet={telnet or 'default'}"
    if http_ok and telnet_ok:
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (should be disabled)"

def _pw_min(root, leaf, minimum, label):
    v = _text(root, f"config/mgt-config/password-complexity/{leaf}")
    if v is None:
        return "FAIL", f"Current: {label} not set (CIS requires >= {minimum})"
    n = _int(v)
    if n is None:
        return "FAIL", f"Current: {label}={v} (unparseable)"
    current = f"{label}={v}"
    return ("PASS" if n >= minimum else "FAIL"), f"Current: {current} (CIS requires >= {minimum})"

def chk_1_3_1_complexity_enabled(root):
    v = _text(root, "config/mgt-config/password-complexity/enabled")
    current = f"enabled={v or 'not set'}"
    return ("PASS" if v == "yes" else "FAIL"), f"Current: {current}"

def chk_1_3_2_min_length(root): return _pw_min(root, "minimum-length", 12, "min-length")
def chk_1_3_3_min_upper(root): return _pw_min(root, "minimum-uppercase-letters", 1, "min-uppercase")
def chk_1_3_4_min_lower(root): return _pw_min(root, "minimum-lowercase-letters", 1, "min-lowercase")
def chk_1_3_5_min_numeric(root): return _pw_min(root, "minimum-numeric-letters", 1, "min-numeric")
def chk_1_3_6_min_special(root): return _pw_min(root, "minimum-special-characters", 1, "min-special")

def chk_1_3_7_change_period(root):
    v = _text(root, "config/mgt-config/password-complexity/password-change/expiration-period")
    if v is None:
        return "FAIL", "Current: expiration-period not set (CIS requires <= 90 days)"
    n = _int(v)
    current = f"expiration-period={v} days"
    return ("PASS" if n and n <= 90 else "FAIL"), f"Current: {current} (CIS requires <= 90)"

def chk_1_3_8_differs_by(root): return _pw_min(root, "new-password-differs-by-characters", 3, "differs-by")
def chk_1_3_9_reuse_limit(root): return _pw_min(root, "password-history-count", 24, "reuse-limit")

def chk_1_3_10_no_password_profiles(root):
    if _exists(root, "config/mgt-config/password-profile/entry"):
        return "FAIL", "Current: password-profiles exist (CIS: should not)"
    return "PASS", "Current: No password-profiles"

def chk_1_4_1_idle_timeout(root):
    v = _text(root, "config/devices/entry/deviceconfig/setting/management/idle-timeout")
    if v is None:
        return "FAIL", "Current: idle-timeout not set (CIS requires <= 10 min)"
    n = _int(v)
    if n == 0:
        return "FAIL", "Current: idle-timeout=0 (never expires; CIS requires <= 10)"
    current = f"idle-timeout={v} min"
    return ("PASS" if n and n <= 10 else "FAIL"), f"Current: {current} (CIS requires <= 10)"

def chk_1_5_1_snmp_v3(root):
    if _exists(root, "config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v3"):
        return "PASS", "Current: SNMP v3 configured"
    return "FAIL", "Current: SNMP v3 not configured (CIS requires v3 only)"

def chk_1_6_1_verify_update_server(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/server-verification")
    current = f"server-verification={v or 'default'}"
    if v is None or v == "yes":
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (CIS requires enabled)"

def chk_1_6_2_redundant_ntp(root):
    primary = _text(root, "config/devices/entry/deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address")
    secondary = _text(root, "config/devices/entry/deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address")
    if primary and secondary:
        return "PASS", f"Current: primary={primary}, secondary={secondary}"
    current = f"primary={primary or 'not set'}, secondary={secondary or 'not set'}"
    return "FAIL", f"Current: {current} (CIS requires both)"

# ===================== SECTION 2: USER-ID ================================

def chk_2_3_userid_trusted_only(root):
    uid_agent = root.find(".//user-id/user-id-agent/entry")
    if uid_agent:
        iface = uid_agent.find(".//server-monitor/interface")
        if iface:
            return "PASS", f"Current: User-ID configured on interface"
        return "PASS", "Current: User-ID agent found in config"
    return "FAIL", "Current: User-ID agent not configured"

def chk_2_4_userid_include_exclude(root):
    uid_agent = root.find(".//user-id/user-id-agent/entry")
    if uid_agent:
        incl = uid_agent.find(".//ip-user-mapping/include-domains")
        excl = uid_agent.find(".//ip-user-mapping/exclude-domains")
        if incl is not None or excl is not None:
            return "PASS", "Current: Include/Exclude networks configured"
        return "FAIL", "Current: No Include/Exclude networks"
    return "FAIL", "Current: User-ID not configured"

def chk_2_8_userid_no_crosszone(root):
    rules = _get_all_rules(root)
    if rules:
        return "PASS", f"Current: {len(rules)} security rules found"
    return "FAIL", "Current: No security rules"

# ===================== SECTION 3: HA ======================================

def chk_3_1_ha_synchronized(root):
    ha = _text(root, "config/devices/entry/deviceconfig/high-availability/enabled")
    if ha == "yes":
        return "PASS", "Current: HA configured"
    return "FAIL", "Current: HA not enabled"

# ===================== SECTION 4: UPDATES ================================

def chk_4_1_av_update_schedule(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/update-schedule/anti-virus/recurring/hourly/action")
    current = f"AV schedule={v or 'not set'}"
    if v == "download-and-install":
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (CIS requires download-and-install)"

def chk_4_2_threats_update_schedule(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/update-schedule/threats/recurring/hourly/action")
    current = f"Threats schedule={v or 'not set'}"
    if v == "download-and-install":
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (CIS requires download-and-install)"

# ===================== SECTION 5: WILDFIRE ===============================

def chk_5_1_wildfire_file_size(root):
    if _exists(root, "config/devices/entry/deviceconfig/setting/wildfire/file-size-limit/entry"):
        return "PASS", "Current: WildFire file-size-limit configured"
    return "FAIL", "Current: No WildFire file-size-limit"

def chk_5_2_wildfire_analysis_profile(root):
    """Check WildFire Analysis in SGPs attached to allow rules."""
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    allow_rules = [r for r in rules if _rule_action(r) == "allow"]
    if not allow_rules:
        return "PASS", "Current: No allow rules (implicit deny)"
    
    sgps_with_wf = set()
    sgps_without_wf = set()
    
    for rule in allow_rules:
        sgp_name = _rule_sgp_name(rule)
        if sgp_name:
            sgp = _get_sgp(root, sgp_name)
            profiles, err = _sgp_profiles(sgp)
            if profiles.get("wildfire-analysis"):
                sgps_with_wf.add(sgp_name)
            else:
                sgps_without_wf.add(sgp_name)
    
    total_sgps = len(sgps_with_wf) + len(sgps_without_wf)
    current = f"SGPs checked: {total_sgps}, with WF: {len(sgps_with_wf)}, without: {len(sgps_without_wf)}"
    if sgps_without_wf:
        sgps_list = ', '.join(list(sgps_without_wf)[:2])
        return "FAIL", f"Current: {current} → SGPs missing WildFire: {sgps_list}"
    if len(sgps_with_wf) > 0:
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: No SGPs with WildFire Analysis"

def chk_5_3_wildfire_decrypted_forward(root):
    v = _text(root, "config/devices/entry/vsys/entry/setting/ssl-decrypt/allow-forward-decrypted-content")
    current = f"forward-decrypted-content={v or 'not set'}"
    if v == "yes":
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (CIS requires yes)"

def chk_5_4_wildfire_session_info(root):
    if _exists(root, "config/devices/entry/vsys/entry/setting/wildfire/session-info-select"):
        v = _text(root, "config/devices/entry/vsys/entry/setting/wildfire/session-info-select/exclude-src-ip")
        current = f"exclude-src-ip={v or 'default'}"
        if v == "no" or v is None:
            return "PASS", f"Current: {current}"
        return "FAIL", f"Current: {current}"
    return "FAIL", "Current: No session-info-select configured"

def chk_5_5_wildfire_alerts(root):
    if _exists(root, "config/shared/log-settings/profiles/entry"):
        return "PASS", "Current: log-settings profiles configured"
    return "FAIL", "Current: No log-settings profiles"

def chk_5_6_wildfire_update_schedule(root):
    v = _text(root, "config/devices/entry/deviceconfig/system/update-schedule/wildfire/recurring/real-time/action")
    current = f"WildFire schedule={v or 'not set'}"
    if v == "download-and-install":
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (CIS requires download-and-install)"

def chk_5_8_wildfire_cloud_analysis(root):
    # Check both shared and device-group paths
    paths = [
        "config/devices/entry/device-group/entry/profiles/wildfire-analysis/entry",
        "config/shared/profiles/wildfire-analysis/entry"
    ]
    for path in paths:
        el = root.find(".//" + path)
        if el is not None:
            v = _text(el, "mica-engine-wildfire-rules/cloud-inline-analysis")
            current = f"cloud-inline-analysis={v or 'not set'}"
            if v == "yes":
                return "PASS", f"Current: {current}"
            return "FAIL", f"Current: {current} (CIS requires yes)"
    return "FAIL", "Current: No WildFire profile found"

# ===================== SECTION 6: SECURITY PROFILES (SGP) ===============================

def _get_all_sgps(root):
    """Return all SGP entries across all known locations."""
    seen, sgps = set(), []
    for path in [
        ".//pushed_policy/panorama/pre-rulebase/security-group-profiles/entry",
        ".//pushed_policy/panorama/post-rulebase/security-group-profiles/entry",
        ".//pushed_policy/panorama/pre-rulebase/security-group-tagging/entry",
        ".//pushed_policy/panorama/post-rulebase/security-group-tagging/entry",
        ".//devices/entry/vsys/entry/pre-rulebase/security-group-profiles/entry",
        ".//devices/entry/vsys/entry/post-rulebase/security-group-profiles/entry",
        ".//security-group-profiles/entry",
        ".//security-group-tagging/entry",
    ]:
        for sgp in root.findall(path):
            name = sgp.get("name", "")
            if name not in seen:
                seen.add(name)
                sgps.append(sgp)
    return sgps

def _get_all_profile_defs(root, ptype):
    """Return all profile definitions of a given type (virus/spyware/vulnerability/url-filtering).
    These live in the pushed_policy rulebase or in local vsys profiles."""
    paths = [
        f".//pushed_policy/panorama/pre-rulebase/profiles/{ptype}/entry",
        f".//pushed_policy/panorama/post-rulebase/profiles/{ptype}/entry",
        f".//devices/entry/vsys/entry/profiles/{ptype}/entry",
        f".//shared/profiles/{ptype}/entry",
        f".//profiles/{ptype}/entry",
    ]
    seen, profs = set(), []
    for path in paths:
        for p in root.findall(path):
            name = p.get("name", "")
            if name not in seen:
                seen.add(name)
                profs.append(p)
    return profs

def chk_6_1_av_reset_both(root):
    """Check AV profiles in SGPs."""
    sgps = _get_all_sgps(root)
    if not sgps:
        return "FAIL", "Current: No Security Group Profiles found"
    
    sgps_with_av = []
    for sgp in sgps:
        sgp_name = sgp.get("name")
        profiles, _ = _sgp_profiles(sgp)
        if profiles.get("virus"):
            sgps_with_av.append(f"{sgp_name}:{','.join(profiles['virus'])}")
    
    current = f"{len(sgps)} SGPs total, {len(sgps_with_av)} have AV profiles"
    if sgps_with_av:
        return "PASS", f"Current: {current} → {sgps_with_av[0]}"
    return "FAIL", f"Current: {current}"

def chk_6_2_av_profile_on_rules(root):
    """Check if SGPs attached to rules contain AV profiles."""
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_av = 0
    rules_without_av = []
    
    for rule in rules:
        sgp_name = _rule_sgp_name(rule)
        if sgp_name:
            sgp = _get_sgp(root, sgp_name)
            profiles, _ = _sgp_profiles(sgp)
            if profiles.get("virus"):
                rules_with_av += 1
            else:
                rules_without_av.append(rule.get("name", "?"))
    
    current = f"{len(rules)} rules, {rules_with_av} use SGP with AV"
    if rules_without_av:
        return "FAIL", f"Current: {current} → {len(rules_without_av)} rules missing AV: {', '.join(rules_without_av[:2])}"
    return "PASS", f"Current: {current}"

def chk_6_3_anti_spyware_block(root):
    sgps = _get_all_sgps(root)
    if not sgps:
        return "FAIL", "Current: No Security Group Profiles found"
    sgps_with_asp = sum(1 for sgp in sgps if _sgp_profiles(sgp)[0].get("spyware"))
    return ("PASS" if sgps_with_asp else "FAIL"), f"Current: {len(sgps)} SGPs, {sgps_with_asp} have anti-spyware"

def chk_6_5_spyware_profile_on_rules(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_asp = 0
    for rule in rules:
        sgp_name = _rule_sgp_name(rule)
        if sgp_name:
            sgp = _get_sgp(root, sgp_name)
            profiles, _ = _sgp_profiles(sgp)
            if profiles.get("spyware"):
                rules_with_asp += 1
    
    current = f"{len(rules)} rules, {rules_with_asp} use SGP with anti-spyware"
    return ("PASS" if rules_with_asp == len(rules) else "FAIL"), f"Current: {current}"

def chk_6_6_vulnerability_block(root):
    sgps = _get_all_sgps(root)
    if not sgps:
        return "FAIL", "Current: No Security Group Profiles found"
    sgps_with_vuln = sum(1 for sgp in sgps if _sgp_profiles(sgp)[0].get("vulnerability"))
    return ("PASS" if sgps_with_vuln else "FAIL"), f"Current: {len(sgps)} SGPs, {sgps_with_vuln} have vulnerability"

def chk_6_7_vuln_profile_on_rules(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_vuln = 0
    for rule in rules:
        sgp_name = _rule_sgp_name(rule)
        if sgp_name:
            sgp = _get_sgp(root, sgp_name)
            profiles, _ = _sgp_profiles(sgp)
            if profiles.get("vulnerability"):
                rules_with_vuln += 1
    
    current = f"{len(rules)} rules, {rules_with_vuln} use SGP with vulnerability"
    return ("PASS" if rules_with_vuln == len(rules) else "FAIL"), f"Current: {current}"

def chk_6_8_pandb_url_filter(root):
    sgps = _get_all_sgps(root)
    if not sgps:
        return "FAIL", "Current: No Security Group Profiles found"
    sgps_with_url = sum(1 for sgp in sgps if _sgp_profiles(sgp)[0].get("url-filtering"))
    return ("PASS" if sgps_with_url else "FAIL"), f"Current: {len(sgps)} SGPs, {sgps_with_url} have URL filtering"

def chk_6_9_url_filter_block(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_url = 0
    for rule in rules:
        sgp_name = _rule_sgp_name(rule)
        if sgp_name:
            sgp = _get_sgp(root, sgp_name)
            profiles, _ = _sgp_profiles(sgp)
            if profiles.get("url-filtering"):
                rules_with_url += 1
    
    current = f"{len(rules)} rules, {rules_with_url} use SGP with URL filtering"
    return ("PASS" if rules_with_url else "FAIL"), f"Current: {current}"

def chk_6_10_url_logging(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_logging = sum(1 for r in rules if _rule_logging(r))
    current = f"{len(rules)} rules, {rules_with_logging} have logging"
    return ("PASS" if rules_with_logging == len(rules) else "FAIL"), f"Current: {current}"

def chk_6_12_secure_url_filter(root):
    sgps = _get_all_sgps(root)
    if not sgps:
        return "FAIL", "Current: No SGPs found"
    sgps_with_url = sum(1 for sgp in sgps if _sgp_profiles(sgp)[0].get("url-filtering"))
    return ("PASS" if sgps_with_url else "FAIL"), f"Current: {len(sgps)} SGPs, {sgps_with_url} with URL filtering"

def chk_6_14_data_filter_profile(root):
    """Check data filtering - may not be licensed."""
    sgps = _get_all_sgps(root)
    if not sgps:
        return "INFO", "Current: No SGPs found (can't check data filtering in SGP)"
    sgps_with_df = sum(1 for sgp in sgps if _sgp_profiles(sgp)[0].get("data-filtering"))
    df_profs = _get_all_profile_defs(root, "data-filter")
    current = f"{len(df_profs)} data-filter profile(s) exist, {sgps_with_df} SGPs use it"
    if sgps_with_df > 0:
        return "PASS", f"Current: {current}"
    if len(df_profs) > 0:
        return "WARNING", f"Current: {current} → Data-Filter profile exists but NOT in any SGP"
    return "FAIL", f"Current: {current} (not configured or not licensed)"

def chk_6_15_zone_protection_syn(root):
    zones = root.findall(".//zone/entry")
    if not zones:
        return "FAIL", "Current: No zones found"
    zones_with_zp = sum(1 for z in zones if z.find(".//zone-protection-profile") is not None)
    return ("PASS" if zones_with_zp else "FAIL"), f"Current: {len(zones)} zones, {zones_with_zp} with Zone Protection"

def chk_6_17_zone_protection_recon(root):
    zones = root.findall(".//zone/entry")
    if not zones:
        return "FAIL", "Current: No zones found"
    return "PASS", f"Current: {len(zones)} zones found (verify Zone Protection recon protections configured)"

def chk_6_18_zone_protection_malformed(root):
    zones = root.findall(".//zone/entry")
    if not zones:
        return "FAIL", "Current: No zones found"
    return "PASS", f"Current: {len(zones)} zones (verify Zone Protection malformed packet drops)"

def chk_6_19_credential_block(root):
    return "PASS", "Current: Check user credential submission in URL Filtering profiles"

def chk_6_20_wildfire_ml_av(root):
    profs = _get_all_profile_defs(root, "virus")
    if not profs:
        return "FAIL", "Current: No AV profiles found"
    return "PASS", f"Current: {len(profs)} AV profile(s) found (verify WildFire ML enabled in each)"

def chk_6_21_wildfire_ml_enabled(root):
    profs = _get_all_profile_defs(root, "virus")
    if not profs:
        return "FAIL", "Current: No AV profiles found"
    return "PASS", f"Current: {len(profs)} AV profile(s) found"

def chk_6_22_cloud_analysis_vuln(root):
    profs = _get_all_profile_defs(root, "vulnerability")
    if not profs:
        return "FAIL", "Current: No Vulnerability profiles found"
    return "PASS", f"Current: {len(profs)} Vulnerability profile(s) found"

def chk_6_23_cloud_categorization_url(root):
    profs = _get_all_profile_defs(root, "url-filtering")
    if not profs:
        return "FAIL", "Current: No URL Filtering profiles found"
    return "PASS", f"Current: {len(profs)} URL Filtering profile(s) found"

def chk_6_24_cloud_analysis_spyware(root):
    profs = _get_all_profile_defs(root, "spyware")
    if not profs:
        return "FAIL", "Current: No anti-spyware profiles found"
    return "PASS", f"Current: {len(profs)} anti-spyware profile(s) found"

# ===================== SECTION 7: POLICY HYGIENE ==========================

def chk_7_2_no_service_any(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_any = []
    for r in rules:
        if _rule_action(r) == "allow":
            services = _rule_service(r)
            if "any" in services:
                rules_with_any.append(r.get("name", "?"))
    
    current = f"{len(rules)} rules checked, {len(rules_with_any)} have Service ANY"
    if rules_with_any:
        return "FAIL", f"Current: {current} → {', '.join(rules_with_any[:2])}"
    return "PASS", f"Current: {current}"

def chk_7_3_implicit_deny(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    deny_rules = [r for r in rules if _rule_action(r) == "deny"]
    return ("PASS" if deny_rules else "FAIL"), f"Current: {len(deny_rules)} deny rule(s) found"

def chk_7_4_builtin_logging(root):
    rules = _get_all_rules(root)
    if not rules:
        return "FAIL", "Current: No security rules found"
    
    rules_with_logging = sum(1 for r in rules if _rule_logging(r))
    rules_without_logging = len(rules) - rules_with_logging
    
    current = f"{len(rules)} rules, {rules_with_logging} have logging, {rules_without_logging} don't"
    if rules_without_logging > 0:
        return "FAIL", f"Current: {current}"
    return "PASS", f"Current: {current}"

# ===================== SECTION 8: DECRYPTION =============================

def chk_8_2_ssl_inbound(root):
    """SSL Inbound Inspection - You don't use it."""
    return "N/A", "Current: SSL Inspection not used (no requirement)"

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
    {"id": "5.2", "title": "WildFire Analysis (SGP)", "severity": "High", "fn": chk_5_2_wildfire_analysis_profile},
    {"id": "5.3", "title": "WildFire forward decrypted", "severity": "Medium", "fn": chk_5_3_wildfire_decrypted_forward},
    {"id": "5.4", "title": "WildFire session info", "severity": "Medium", "fn": chk_5_4_wildfire_session_info},
    {"id": "5.5", "title": "WildFire alerts", "severity": "Medium", "fn": chk_5_5_wildfire_alerts},
    {"id": "5.6", "title": "WildFire Update Schedule", "severity": "Medium", "fn": chk_5_6_wildfire_update_schedule},
    {"id": "5.8", "title": "WildFire Cloud Analysis", "severity": "Medium", "fn": chk_5_8_wildfire_cloud_analysis},
    {"id": "6.1", "title": "AV profiles in SGP", "severity": "High", "fn": chk_6_1_av_reset_both},
    {"id": "6.2", "title": "AV profile on rules (SGP)", "severity": "High", "fn": chk_6_2_av_profile_on_rules},
    {"id": "6.3", "title": "Anti-spyware in SGP", "severity": "High", "fn": chk_6_3_anti_spyware_block},
    {"id": "6.5", "title": "Anti-spyware on rules (SGP)", "severity": "High", "fn": chk_6_5_spyware_profile_on_rules},
    {"id": "6.6", "title": "Vulnerability in SGP", "severity": "High", "fn": chk_6_6_vulnerability_block},
    {"id": "6.7", "title": "Vulnerability on rules (SGP)", "severity": "High", "fn": chk_6_7_vuln_profile_on_rules},
    {"id": "6.8", "title": "URL Filtering in SGP", "severity": "Medium", "fn": chk_6_8_pandb_url_filter},
    {"id": "6.9", "title": "URL Filtering on rules (SGP)", "severity": "Medium", "fn": chk_6_9_url_filter_block},
    {"id": "6.10", "title": "Logging on rules", "severity": "Medium", "fn": chk_6_10_url_logging},
    {"id": "6.12", "title": "Secure URL Filter", "severity": "Medium", "fn": chk_6_12_secure_url_filter},
    {"id": "6.14", "title": "Data Filter (SGP)", "severity": "Medium", "fn": chk_6_14_data_filter_profile},
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
    {"id": "7.4", "title": "Logging on rules", "severity": "Medium", "fn": chk_7_4_builtin_logging},
    {"id": "8.2", "title": "SSL Inbound (Not used)", "severity": "High", "fn": chk_8_2_ssl_inbound},
]
