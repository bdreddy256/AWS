# ---- User-ID scope detection (CIS 2.3 / 2.4) ----
#
# User-ID enablement is a ZONE property in PAN-OS:
#   zone/entry/enable-user-identification = yes
# A zone maps to interfaces, so "User-ID on an interface" == its zone has it on.
#
# CIS 2.3 logic: if User-ID is enabled on NO zone, it's compliant by absence
# (can't be on an untrusted zone if it's on none). If enabled, verify none of
# the enabled zones are untrusted.
#
# Populate with YOUR external zone names for a clean auto-PASS/FAIL. If left
# empty, an enabled-User-ID device returns MANUAL (evidence handed to auditor)
# rather than a possibly-false PASS.
_KNOWN_UNTRUSTED_ZONES = {
    # "l3-untrust", "internet", "outside", "GP-external",   <-- fill in from your GP firewalls
}


def _zones_with_userid(root):
    """Return names of zones with User-ID enabled."""
    out = []
    for z in root.findall(".//zone/entry"):
        v = z.findtext(".//enable-user-identification")
        if v and v.strip().lower() == "yes":
            out.append(z.get("name", "?"))
    return out


def chk_2_3_userid_trusted_only(root):
    """
    CIS 2.3: User-ID must not be enabled on untrusted zones.
      - No zone has User-ID enabled -> PASS (compliant by absence).
      - Enabled zones, none untrusted -> PASS.
      - Any untrusted zone -> FAIL.
      - Enabled but trust list empty -> MANUAL (verify).
    """
    uid_zones = _zones_with_userid(root)

    if not uid_zones:
        return "PASS", "Current: User-ID not enabled on any zone (compliant by absence — cannot be on an untrusted zone)"

    hits = [z for z in uid_zones if z in _KNOWN_UNTRUSTED_ZONES]
    if hits:
        return "FAIL", (f"Current: User-ID enabled on UNTRUSTED zone(s): "
                        f"{', '.join(hits)}. CIS 2.3 violation")

    if _KNOWN_UNTRUSTED_ZONES:
        return "PASS", (f"Current: User-ID enabled on {len(uid_zones)} zone(s): "
                        f"{', '.join(uid_zones[:6])}; none in untrusted set")

    return "MANUAL", (f"Current: User-ID enabled on: {', '.join(uid_zones[:6])}. "
                      f"Verify none are untrusted "
                      f"(populate _KNOWN_UNTRUSTED_ZONES for auto-PASS/FAIL)")


def chk_2_4_userid_include_exclude(root):
    """
    CIS 2.4: Include/Exclude networks defined to bound User-ID scope.
    N/A if User-ID is not enabled on any zone. If enabled, require the
    include/exclude list to be present.
    """
    uid_zones = _zones_with_userid(root)

    if not uid_zones:
        return "N/A", "Current: User-ID not enabled on any zone — include/exclude scope not applicable"

    inc_exc = root.findall(".//ip-user-mapping/include-exclude-network/entry")
    if not inc_exc:
        # alternate PAN-OS layouts (agent / redistribution)
        inc_exc = root.findall(".//user-id/*/include-exclude-network/entry")

    if inc_exc:
        names = [e.get("name", "?") for e in inc_exc]
        return "PASS", f"Current: {len(inc_exc)} include/exclude network(s): {', '.join(names[:4])}"
    return "FAIL", ("Current: User-ID enabled but NO include/exclude networks defined "
                    "(CIS 2.4: scope must be bounded)")
