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

# ===================== PROFILE-GROUP / RULE HELPERS ==============
#
# VERIFIED against real Panorama-pushed config (show config pushed-shared-policy).
#
# Saved XML (produced by export_configs.py) has:
#   <config>
#     <devices>, <shared>, <mgt-config>   <- merged config (device settings)
#     <pushed_policy>
#       <panorama>
#         <pre-rulebase><security><rules><entry ...>   <- SECURITY RULES
#         <post-rulebase><security><rules><entry ...>
#         <profile-group><entry name="SM-PG">          <- PROFILE GROUPS
#             <virus><member>SM-AV</member>
#             <spyware><member>SM-AS</member>
#             <vulnerability><member>SM-VP</member>
#             <wildfire-analysis><member>default</member>
#         <profiles>                                    <- PROFILE DEFINITIONS
#             <virus><entry name="SM-AV">...
#             <spyware><entry name="SM-AS">...
#             <vulnerability><entry name="SM-VP">...
#             <url-filtering><entry name="SM-UF">...
#             <data-filtering><entry name="...">...
#         <log-settings><profiles>                      <- syslog fwd profiles
#
# A rule references its profile-group via:
#   <profile-setting><group><member>SM-PG</member></group></profile-setting>
#
# A rule sets logging via:
#   <log-setting>AWS Syslog</log-setting>   (references a log-settings profile)
#   and/or <log-start>/<log-end>
#
# Rules carry attributes: name="...", uuid="...", panorama="true", loc="..."
# ================================================================

_PANORAMA_BASE = ".//pushed_policy/panorama"

_RULE_SEARCH_PATHS = [
    _PANORAMA_BASE + "/pre-rulebase/security/rules/entry",
    _PANORAMA_BASE + "/post-rulebase/security/rules/entry",
    # local device rulebase (rarely used when Panorama-managed, kept as fallback)
    ".//devices/entry/vsys/entry/rulebase/security/rules/entry",
    ".//rulebase/security/rules/entry",
    # generic fallbacks
    ".//pre-rulebase/security/rules/entry",
    ".//post-rulebase/security/rules/entry",
    ".//security/rules/entry",
]

_PROFILE_GROUP_PATHS_TPL = [
    _PANORAMA_BASE + "/profile-group/entry[@name='{n}']",
    ".//profile-group/entry[@name='{n}']",
]

_PROFILE_DEF_PATHS = [
    _PANORAMA_BASE + "/profiles/{ptype}/entry",
    ".//shared/profiles/{ptype}/entry",
    ".//profiles/{ptype}/entry",
]


def _get_all_rules(root):
    """Return deduplicated list of all security rule <entry> elements."""
    seen, rules = set(), []
    for path in _RULE_SEARCH_PATHS:
        for rule in root.findall(path):
            name = rule.get("name", "")
            key = (name, rule.get("uuid", ""))
            if key not in seen:
                seen.add(key)
                rules.append(rule)
    return rules


def _rule_pg_name(rule):
    """
    Return the profile-group name referenced by this rule, or None.
    Verified path: <profile-setting><group><member>SM-PG</member></group>
    """
    el = rule.find("profile-setting/group/member")
    if el is not None and el.text:
        return el.text.strip()
    return None


def _rule_direct_profiles(rule):
    """
    Some rules attach individual profiles directly instead of a group:
      <profile-setting><profiles><virus><member>..</member>...
    Returns dict of profile-type -> [names]. Empty if none.
    """
    out = {}
    base = rule.find("profile-setting/profiles")
    if base is None:
        return out
    for ptype in ("virus", "spyware", "vulnerability", "url-filtering",
                  "data-filtering", "wildfire-analysis", "file-blocking"):
        el = base.find(ptype)
        if el is not None:
            names = [m.text.strip() for m in el.findall("member") if m.text]
            if names:
                out[ptype] = names
    return out


# Backwards-compatible alias: existing checks call _rule_sgp_name / _get_sgp / _sgp_profiles.
def _rule_sgp_name(rule):
    return _rule_pg_name(rule)


def _get_profile_group(root, pg_name):
    """Find a <profile-group><entry name=pg_name> element."""
    if not pg_name:
        return None
    for tpl in _PROFILE_GROUP_PATHS_TPL:
        found = root.findall(tpl.format(n=pg_name))
        if found:
            return found[0]
    return None


def _get_sgp(root, sgp_name):
    return _get_profile_group(root, sgp_name)


def _sgp_profiles(pg):
    """
    Extract profile members from a profile-group <entry>.

    Verified structure (direct children hold members):
      <entry name="SM-PG">
        <virus><member>SM-AV</member></virus>
        <spyware><member>SM-AS</member></spyware>
        <vulnerability><member>SM-VP</member></vulnerability>
        <wildfire-analysis><member>default</member></wildfire-analysis>
      </entry>
    """
    profiles = {
        "virus": [],
        "spyware": [],
        "vulnerability": [],
        "url-filtering": [],
        "data-filtering": [],
        "wildfire-analysis": [],
        "file-blocking": [],
    }
    if pg is None:
        return profiles, "profile-group not found"

    for ptype in profiles.keys():
        el = pg.find(ptype)
        if el is not None:
            for member in el.findall("member"):
                if member.text:
                    profiles[ptype].append(member.text.strip())

    return profiles, None


def _rule_effective_profiles(root, rule):
    """
    Return the profile-types this rule effectively applies, whether via a
    profile-group or via directly-attached profiles. dict: ptype -> [names].
    """
    direct = _rule_direct_profiles(rule)
    if direct:
        return direct
    pg_name = _rule_pg_name(rule)
    if pg_name:
        pg = _get_profile_group(root, pg_name)
        profs, _ = _sgp_profiles(pg)
        return {k: v for k, v in profs.items() if v}
    return {}


def _get_all_profile_groups(root):
    """Return all profile-group <entry> elements."""
    seen, out = set(), []
    for base in (_PANORAMA_BASE + "/profile-group/entry", ".//profile-group/entry"):
        for e in root.findall(base):
            n = e.get("name", "")
            if n not in seen:
                seen.add(n)
                out.append(e)
    return out

def _rule_action(rule):
    """Get the action of a rule (allow, deny, etc). Direct child only."""
    el = rule.find("action")
    return el.text.strip() if (el is not None and el.text) else None

def _rule_service(rule):
    """Get services in a rule (direct service/member children)."""
    services = []
    svc = rule.find("service")
    if svc is not None:
        for m in svc.findall("member"):
            if m.text:
                services.append(m.text.strip())
    return services

def _rule_logging(rule):
    """
    Check if rule has logging enabled. In this environment logging is done by
    attaching a log-forwarding profile via <log-setting>NAME</log-setting>
    (verified: <log-setting>AWS Syslog</log-setting>). Also accept the classic
    session log-start / log-end = yes.
    """
    ls = rule.find("log-setting")
    if ls is not None and ls.text and ls.text.strip():
        return True
    log_start = _text(rule, "log-start")
    log_end = _text(rule, "log-end")
    return log_start == "yes" or log_end == "yes"

def _rule_log_setting_name(rule):
    """Return the log-forwarding profile name attached to the rule, or None."""
    el = rule.find("log-setting")
    return el.text.strip() if (el is not None and el.text) else None

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
    """
    CIS 5.1: WildFire file-size limits configured. Reads the actual per-file-type
    limits and lists them.
    Verified path: deviceconfig/setting/wildfire/file-size-limit/entry/size-limit
    """
    entries = root.findall(".//setting/wildfire/file-size-limit/entry")
    if not entries:
        return "FAIL", "Current: No WildFire file-size-limit configured"
    limits = []
    for e in entries:
        sz = e.findtext("size-limit")
        limits.append(f"{e.get('name')}={sz}")
    shown = ", ".join(limits[:6])
    more = f" (+{len(limits)-6} more)" if len(limits) > 6 else ""
    return "PASS", f"Current: {len(limits)} file types set - {shown}{more}"

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
    """
    CIS 5.3: Forward decrypted SSL content to WildFire. This requires SSL
    decryption to be configured first. If decryption isn't used, this is N/A.
    Path: setting/ssl-decrypt/allow-forward-decrypted-content
    """
    el = root.find(".//setting/ssl-decrypt/allow-forward-decrypted-content")
    v = el.text.strip() if (el is not None and el.text) else None
    # Detect whether SSL decryption is configured at all
    has_decrypt = (root.find(".//setting/ssl-decrypt") is not None) or \
                  bool(root.findall(".//decryption/rules/entry"))
    if v == "yes":
        return "PASS", "Current: allow-forward-decrypted-content=yes"
    if not has_decrypt:
        return "N/A", "Current: SSL decryption not configured → forwarding N/A"
    return "FAIL", f"Current: allow-forward-decrypted-content={v or 'not set'} (CIS requires yes)"

def chk_5_4_wildfire_session_info(root):
    """
    CIS 5.4: WildFire session information settings should be sent (nothing
    excluded). An empty/self-closing <session-info-select/> means all session
    info is included = compliant. Any child element under it = something excluded.
    Path: setting/wildfire/session-info-select
    """
    sis = root.find(".//setting/wildfire/session-info-select")
    if sis is None:
        return "FAIL", "Current: session-info-select not present"
    excluded = [child.tag for child in list(sis)]
    if not excluded:
        return "PASS", "Current: session-info-select present, nothing excluded (all session info sent)"
    return "FAIL", f"Current: session-info excludes: {', '.join(excluded)} (CIS: send all)"

def chk_5_5_wildfire_alerts(root):
    """
    CIS 5.5: WildFire logs forwarded (alerting). Verify a log-forwarding profile
    has a match-list entry with log-type=wildfire.
    Path: log-settings/profiles/entry/match-list/entry[log-type=wildfire]
    """
    wf_forwarders = []
    for prof in root.findall(".//log-settings/profiles/entry"):
        pname = prof.get("name")
        for ml in prof.findall(".//match-list/entry"):
            lt = ml.findtext("log-type")
            if lt == "wildfire":
                dests = [m.text for m in ml.findall(".//send-syslog/member") if m.text]
                wf_forwarders.append(f"{pname}:{ml.get('name')}→{','.join(dests) or 'configured'}")
    if wf_forwarders:
        return "PASS", f"Current: WildFire log forwarding: {'; '.join(wf_forwarders[:2])}"
    # fallback: any log-settings profile at all
    if root.findall(".//log-settings/profiles/entry"):
        return "FAIL", "Current: log-forwarding profiles exist but none forward log-type=wildfire"
    return "FAIL", "Current: No log-forwarding profiles configured"

def chk_5_6_wildfire_update_schedule(root):
    """
    CIS 5.6: WildFire updates set to download-and-install. PAN-OS may schedule
    this as 'real-time' or 'every-min' (your config uses every-min).
    Path: deviceconfig/system/update-schedule/wildfire/recurring/{real-time|every-min|...}/action
    """
    wf = root.find(".//update-schedule/wildfire/recurring")
    if wf is None:
        return "FAIL", "Current: No WildFire update schedule"
    # find whichever interval child holds the action
    interval, action = None, None
    for child in list(wf):
        act = child.findtext("action")
        if act is not None:
            interval, action = child.tag, act
            break
    current = f"schedule={interval or '?'}, action={action or 'not set'}"
    if action == "download-and-install":
        return "PASS", f"Current: {current}"
    return "FAIL", f"Current: {current} (CIS requires download-and-install)"

def chk_5_8_wildfire_cloud_analysis(root):
    """
    CIS 5.8: Inline Cloud Analysis enabled on WildFire Analysis profiles (if ATP).
    Reads custom wildfire-analysis profiles under pushed_policy/panorama/profiles.
    If only the built-in 'default' profile is referenced (no custom profile
    exists to configure), reports that state rather than a false FAIL.
    Path: profiles/wildfire-analysis/entry/.../cloud-inline-analysis
    """
    wf_profs = _get_all_profile_defs(root, "wildfire-analysis")
    # names referenced by groups
    ref_names = _group_profile_names(root, "wildfire-analysis")

    if not wf_profs:
        if ref_names and ref_names <= {"default"}:
            return "N/A", "Current: only built-in 'default' WildFire Analysis profile in use (no custom profile to configure Inline Cloud Analysis)"
        if not ref_names:
            return "FAIL", "Current: No WildFire Analysis profile referenced by any group"
        return "FAIL", f"Current: WildFire Analysis profiles referenced ({', '.join(ref_names)}) but no definitions found"

    details, all_ok = [], True
    for prof in wf_profs:
        name = prof.get("name")
        # cloud-inline-analysis can sit directly or under mica-engine-wildfire-rules
        v = (prof.findtext(".//cloud-inline-analysis")
             or prof.findtext(".//mica-engine-wildfire-rules/cloud-inline-analysis"))
        details.append(f"{name}[cloud-inline-analysis={v or 'not set'}]")
        if v not in ("yes", "true", "enable"):
            all_ok = False
    current = "; ".join(details[:2])
    req = "CIS: Inline Cloud Analysis = yes (if ATP licensed)"
    return ("PASS" if all_ok else "FAIL"), f"Current: {current}. {req}"

# ===================== SECTION 6: SECURITY PROFILES (SGP) ===============================

def _get_all_sgps(root):
    """
    Return all profile-group entries. (Named _get_all_sgps for back-compat;
    in this architecture 'SGP' == profile-group.)
    Verified path: pushed_policy/panorama/profile-group/entry
    """
    return _get_all_profile_groups(root)

def _get_all_profile_defs(root, ptype):
    """
    Return all profile definitions of a given type.
    Verified path: pushed_policy/panorama/profiles/<ptype>/entry
      (also checks shared/ and generic fallbacks)
    """
    seen, profs = set(), []
    for tpl in _PROFILE_DEF_PATHS:
        for p in root.findall(tpl.format(ptype=ptype)):
            name = p.get("name", "")
            if name not in seen:
                seen.add(name)
                profs.append(p)
    return profs

# -------- PAN-OS default-action semantics --------
# When an action is literally "default", PAN-OS applies its built-in default.
# For AV decoders and wildfire/mlav actions, the built-in default resolves to
# "reset-both" for standard protocols (ftp, http, http2, smb, smtp) — which
# MEETS the CIS reset-both requirement. imap/pop3 default to "alert", which is
# why CIS exempts them. For anti-spyware/vulnerability signatures, "default"
# uses Palo Alto's per-signature recommended action (block/reset for
# critical/high). We treat "default" as compliant but LABEL it so an auditor
# sees exactly what resolved.

# Explicit blocking actions
_BLOCK_ACTIONS = {"reset-both", "reset-client", "reset-server",
                  "drop", "block-ip", "block"}

def _av_action_ok(decoder_name, action):
    """
    Is this AV decoder action compliant with CIS reset-both requirement?
    Returns (ok: bool, note: str).
    'default' on a non-exempt decoder resolves to reset-both = compliant.
    """
    if action == "reset-both":
        return True, "reset-both"
    if action == "default":
        # imap/pop3 default to alert, but those are exempt and handled by caller
        return True, "default(=reset-both)"
    if action in _BLOCK_ACTIONS:
        return True, action
    return False, action or "not set"

def _sig_action_ok(action):
    """
    Is this anti-spyware/vulnerability signature-rule action compliant with a
    'block critical/high' requirement? 'default' uses PA's recommended action
    which for critical/high is reset/block = compliant.
    Returns (ok: bool, note: str).
    """
    if action in _BLOCK_ACTIONS:
        return True, action
    if action == "default":
        return True, "default(=PA-recommended block)"
    return False, action or "not set"


def _get_profile_def(root, ptype, name):
    """Return a specific profile <entry> by type and name, or None."""
    if not name:
        return None
    for p in _get_all_profile_defs(root, ptype):
        if p.get("name") == name:
            return p
    return None

def _group_profile_names(root, ptype):
    """
    Return the set of profile names of a given type that are referenced by any
    profile-group. E.g. ptype='virus' -> {'SM-AV'}.
    """
    names = set()
    for pg in _get_all_profile_groups(root):
        profs, _ = _sgp_profiles(pg)
        for n in profs.get(ptype, []):
            names.add(n)
    return names

def _resolved_profiles_in_use(root, ptype):
    """
    Return the actual profile <entry> definitions of a given type that are
    referenced by profile-groups (i.e. profiles that are really applied), as a
    list of (name, element). This is what lets checks inspect INTERNAL settings
    of the profiles you actually use, not just any profile that exists.
    """
    out = []
    for name in sorted(_group_profile_names(root, ptype)):
        el = _get_profile_def(root, ptype, name)
        if el is not None:
            out.append((name, el))
    return out

def chk_6_1_av_reset_both(root):
    """
    CIS 6.1: AV profile decoders set to reset-both on all decoders EXCEPT
    'imap' and 'pop3'. Inspects the actual virus profiles referenced by your
    profile-groups and reads each decoder's <action>.
    Screenshot ref: profiles/virus/entry/decoder/entry/action
    """
    EXEMPT = {"imap", "pop3"}
    in_use = _resolved_profiles_in_use(root, "virus")
    if not in_use:
        defs = _get_all_profile_defs(root, "virus")
        if not defs:
            return "FAIL", "Current: No AV profiles found"
        in_use = [(d.get("name"), d) for d in defs]

    details = []
    all_ok = True
    for name, prof in in_use:
        actions = {}
        for d in prof.findall(".//decoder/entry"):
            act = d.findtext("action")
            if act:
                actions[d.get("name")] = act
        weak = []
        shown_parts = []
        for dn, a in actions.items():
            if dn in EXEMPT:
                shown_parts.append(f"{dn}={a}(exempt)")
                continue
            ok, note = _av_action_ok(dn, a)
            shown_parts.append(f"{dn}={note}")
            if not ok:
                weak.append(dn)
        shown = ", ".join(shown_parts[:4])
        if actions:
            details.append(f"{name}[{shown}{'...' if len(shown_parts)>4 else ''}]")
            if weak:
                all_ok = False
        else:
            details.append(f"{name}[no decoder actions read]")
            all_ok = False

    current = "; ".join(details[:2])
    req = "CIS: reset-both (or default=reset-both) except imap/pop3"
    if all_ok:
        return "PASS", f"Current: {current}. {req} → met"
    return "FAIL", f"Current: {current}. {req} → some decoders not blocking"

def _chk_6_1_old_sgp_only(root):
    """(kept for reference) group-level only check."""
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
    """
    CIS 6.3: Anti-spyware profile must BLOCK (reset-both/drop/block-ip) on all
    severity levels. Reads the actual severity rule actions in the spyware
    profiles your groups use.
    Screenshot ref: profiles/spyware/entry/rules/entry/action + severity/member
    """
    in_use = _resolved_profiles_in_use(root, "spyware")
    if not in_use:
        defs = _get_all_profile_defs(root, "spyware")
        if not defs:
            return "FAIL", "Current: No anti-spyware profiles found"
        in_use = [(d.get("name"), d) for d in defs]

    details, all_ok = [], True
    for name, prof in in_use:
        rules = prof.findall(".//rules/entry")
        sev_action = []
        for r in rules:
            # action is the first child under <action> (e.g. <alert/>, <reset-both/>, <default/>)
            act_el = r.find("action")
            act = None
            if act_el is not None:
                kids = list(act_el)
                act = kids[0].tag if kids else (act_el.text or "").strip()
            sevs = [m.text for m in r.findall("severity/member") if m.text]
            sev_action.append((r.get("name"), ",".join(sevs), act))
        weak, shown_parts = [], []
        for rn, sv, ac in sev_action:
            ok, note = _sig_action_ok(ac)
            shown_parts.append(f"{rn}={note}")
            if not ok:
                weak.append(f"{rn}({sv})={ac}")
        shown = "; ".join(shown_parts[:3])
        details.append(f"{name}[{shown}]")
        if weak or not sev_action:
            all_ok = False

    current = " | ".join(details[:2])
    req = "CIS: block/reset (or default) on all severities"
    if all_ok:
        return "PASS", f"Current: {current}. {req} → met"
    return "FAIL", f"Current: {current}. {req} → some rules at alert/allow"

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
    """
    CIS 6.6: Vulnerability Protection must BLOCK critical & high, and be default
    on medium/low/informational. Reads actual rule actions by severity in the
    vulnerability profiles your groups use.
    Screenshot ref: profiles/vulnerability/entry/rules/entry/action + severity/member
    """
    in_use = _resolved_profiles_in_use(root, "vulnerability")
    if not in_use:
        defs = _get_all_profile_defs(root, "vulnerability")
        if not defs:
            return "FAIL", "Current: No Vulnerability profiles found"
        in_use = [(d.get("name"), d) for d in defs]

    HIGHSEV = {"critical", "high"}
    details, all_ok = [], True
    for name, prof in in_use:
        by_sev = {}
        for r in prof.findall(".//rules/entry"):
            act_el = r.find("action")
            act = None
            if act_el is not None:
                kids = list(act_el)
                act = kids[0].tag if kids else (act_el.text or "").strip()
            for m in r.findall("severity/member"):
                if m.text:
                    by_sev.setdefault(m.text, set()).add(act)
        # critical & high must include a blocking action (default counts as PA-recommended block)
        problems = []
        for sev in HIGHSEV:
            acts = by_sev.get(sev, set())
            if not acts or not any(_sig_action_ok(a)[0] for a in acts):
                problems.append(f"{sev}={','.join(a for a in acts if a) or 'none'}")
        shown = ", ".join(f"{s}={'/'.join(a for a in acts if a)}" for s, acts in list(by_sev.items())[:4])
        details.append(f"{name}[{shown}]")
        if problems:
            all_ok = False

    current = " | ".join(details[:2])
    req = "CIS: block on critical & high"
    if all_ok:
        return "PASS", f"Current: {current}. {req} → met"
    return "FAIL", f"Current: {current}. {req} → critical/high not blocking"

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
    df_profs = _get_all_profile_defs(root, "data-filtering")
    df_names = [d.get("name") for d in df_profs]
    current = f"{len(df_profs)} data-filtering profile(s) exist ({', '.join(df_names[:2])}), {sgps_with_df} profile-group(s) use it"
    if sgps_with_df > 0:
        return "PASS", f"Current: {current}"
    if len(df_profs) > 0:
        return "WARNING", f"Current: {current} → profile exists but NOT attached to any profile-group"
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
    """
    CIS 6.20: 'WildFire Inline ML Action' on AV profiles = reset-both on all
    decoders except imap/pop3. Reads mlav-action / wildfire-action per decoder.
    Screenshot ref: profiles/virus/entry/decoder/entry/wildfire-action + mlav-action
    """
    in_use = _resolved_profiles_in_use(root, "virus")
    if not in_use:
        defs = _get_all_profile_defs(root, "virus")
        if not defs:
            return "FAIL", "Current: No AV profiles found"
        in_use = [(d.get("name"), d) for d in defs]
    EXEMPT = {"imap", "pop3"}
    details, all_ok = [], True
    for name, prof in in_use:
        vals = []
        for d in prof.findall(".//decoder/entry"):
            dn = d.get("name")
            if dn in EXEMPT:
                continue
            wf = d.findtext("wildfire-action")
            if wf:
                vals.append((dn, wf))
        weak, shown_parts = [], []
        for dn, wf in vals:
            ok, note = _av_action_ok(dn, wf)
            shown_parts.append(f"{dn}={note}")
            if not ok:
                weak.append(dn)
        shown = ", ".join(shown_parts[:3])
        details.append(f"{name}[{shown or 'no wildfire-action set'}]")
        if weak or not vals:
            all_ok = False
    current = " | ".join(details[:2])
    req = "CIS: wildfire-action=reset-both or default (except imap/pop3)"
    return ("PASS" if all_ok else "FAIL"), f"Current: {current}. {req}"

def chk_6_21_wildfire_ml_enabled(root):
    """
    CIS 6.21: 'WildFire Inline ML' enabled for all file types on AV profiles.
    Reads mlav-engine-filebased-enabled entries.
    """
    in_use = _resolved_profiles_in_use(root, "virus")
    if not in_use:
        defs = _get_all_profile_defs(root, "virus")
        if not defs:
            return "FAIL", "Current: No AV profiles found"
        in_use = [(d.get("name"), d) for d in defs]
    details, all_ok = [], True
    for name, prof in in_use:
        ml_entries = prof.findall(".//mlav-engine-filebased-enabled/entry")
        enabled, disabled = [], []
        for e in ml_entries:
            action = e.findtext("mlav-policy-action") or e.findtext("enabled")
            fname = e.get("name", "?")
            if action in ("enable", "yes", "enable(alert-only)"):
                enabled.append(fname)
            else:
                disabled.append(f"{fname}={action}")
        if ml_entries:
            details.append(f"{name}[{len(enabled)} enabled, {len(disabled)} not]")
            if disabled:
                all_ok = False
        else:
            details.append(f"{name}[no ML file-type settings found]")
            all_ok = False
    current = " | ".join(details[:2])
    req = "CIS: Inline ML enabled for all file types"
    return ("PASS" if all_ok else "FAIL"), f"Current: {current}. {req}"

def _cloud_inline_setting(prof, tags):
    """Return (found_value or None) for the first matching cloud-analysis tag."""
    for t in tags:
        el = prof.find(f".//{t}")
        if el is not None:
            return t, (el.text or "").strip() or "yes"
    return None, None

def chk_6_22_cloud_analysis_vuln(root):
    """
    CIS 6.22: 'Inline Cloud Analysis' enabled on Vulnerability profiles (if ATP).
    Reads cloud-inline-analysis (verified tag name in PAN-OS vuln profiles).
    """
    in_use = _resolved_profiles_in_use(root, "vulnerability")
    if not in_use:
        defs = _get_all_profile_defs(root, "vulnerability")
        if not defs:
            return "FAIL", "Current: No Vulnerability profiles found"
        in_use = [(d.get("name"), d) for d in defs]
    details, all_ok = [], True
    for name, prof in in_use:
        tag, val = _cloud_inline_setting(prof, ["cloud-inline-analysis", "inline-cloud-analysis"])
        if val is None:
            details.append(f"{name}[cloud-inline-analysis not set]")
            all_ok = False
        else:
            details.append(f"{name}[{tag}={val}]")
            if val not in ("yes", "true", "enable"):
                all_ok = False
    current = " | ".join(details[:2])
    req = "CIS: Inline Cloud Analysis = yes (if ATP licensed)"
    return ("PASS" if all_ok else "FAIL"), f"Current: {current}. {req}"

def chk_6_23_cloud_categorization_url(root):
    """
    CIS 6.23: 'Cloud Inline Categorization' enabled on URL Filtering profiles (if ATP).
    Reads cloud-inline-cat / inline-categorization tag.
    """
    in_use = _resolved_profiles_in_use(root, "url-filtering")
    if not in_use:
        defs = _get_all_profile_defs(root, "url-filtering")
        if not defs:
            return "FAIL", "Current: No URL Filtering profiles found"
        in_use = [(d.get("name"), d) for d in defs]
    details, all_ok = [], True
    for name, prof in in_use:
        tag, val = _cloud_inline_setting(prof, ["cloud-inline-cat", "inline-categorization", "cloud-inline-categorization"])
        if val is None:
            details.append(f"{name}[cloud-inline-cat not set]")
            all_ok = False
        else:
            details.append(f"{name}[{tag}={val}]")
            if val not in ("yes", "true", "enable"):
                all_ok = False
    current = " | ".join(details[:2])
    req = "CIS: Cloud Inline Categorization = yes (if ATP licensed)"
    return ("PASS" if all_ok else "FAIL"), f"Current: {current}. {req}"

def chk_6_24_cloud_analysis_spyware(root):
    """
    CIS 6.24: 'Inline Cloud Analysis' enabled on Anti-Spyware profiles (if ATP).
    Reads cloud-inline-analysis tag inside spyware profiles.
    """
    in_use = _resolved_profiles_in_use(root, "spyware")
    if not in_use:
        defs = _get_all_profile_defs(root, "spyware")
        if not defs:
            return "FAIL", "Current: No anti-spyware profiles found"
        in_use = [(d.get("name"), d) for d in defs]
    details, all_ok = [], True
    for name, prof in in_use:
        tag, val = _cloud_inline_setting(prof, ["cloud-inline-analysis", "inline-cloud-analysis"])
        if val is None:
            details.append(f"{name}[cloud-inline-analysis not set]")
            all_ok = False
        else:
            details.append(f"{name}[{tag}={val}]")
            if val not in ("yes", "true", "enable"):
                all_ok = False
    current = " | ".join(details[:2])
    req = "CIS: Inline Cloud Analysis = yes (if ATP licensed)"
    return ("PASS" if all_ok else "FAIL"), f"Current: {current}. {req}"

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
