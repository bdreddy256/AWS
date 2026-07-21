# CIS 5.1 required MAXIMUM file-size upload limits (PAN-OS 9.x+), in the units
# 'show wildfire status' prints. Source: CIS PAN-OS 11 Benchmark 5.1.
_WF_MAX = {
    "pe": ("50", "MB"), "apk": ("50", "MB"), "pdf": ("51200", "KB"),
    "ms-office": ("51200", "KB"), "jar": ("20", "MB"), "flash": ("10", "MB"),
    "macosx": ("50", "MB"), "archive": ("50", "MB"), "linux": ("50", "MB"),
    "script": ("4096", "KB"),
}

def _wf_status_limits(root):
    """
    Return {type: (value, unit)} from injected wildfire op-state, or {}.
    Injected by audit.py as: op_state/wildfire/file-size-limits/entry
        <entry name="pe"><value>16</value><unit>MB</unit></entry>
    """
    out = {}
    for e in root.findall(".//op_state/wildfire/file-size-limits/entry"):
        name = (e.get("name") or "").strip().lower()
        val = (e.findtext("value") or "").strip()
        unit = (e.findtext("unit") or "").strip()
        if name and val:
            out[name] = (val, unit)
    return out


def chk_5_1_wildfire_file_size(root):
    """
    CIS 5.1: WildFire file-size upload limits set to the MAXIMUM values.
    Primary source: parsed 'show wildfire status' op-state (effective values,
    including defaults). Falls back to config XML if op-state absent (offline).
    """
    limits = _wf_status_limits(root)

    if not limits:
        for e in root.findall(".//setting/wildfire/file-size-limit/entry"):
            name = (e.get("name") or "").strip().lower()
            sz = (e.findtext("size-limit") or e.findtext("size") or "").strip()
            if name and sz:
                limits[name] = (sz, "")
        if not limits:
            return "FAIL", ("Current: WildFire file-size not readable "
                            "(no op-state; not in config = running defaults). "
                            "CIS 5.1 requires MAX limits -> remediate.")

    below, shown = [], []
    for ftype, (maxval, maxunit) in _WF_MAX.items():
        cur = limits.get(ftype)
        if cur is None:
            below.append(f"{ftype}=missing")
            continue
        cval, cunit = cur
        shown.append(f"{ftype}={cval}{cunit or maxunit}")
        try:
            if int(cval) < int(maxval):
                below.append(f"{ftype}={cval}{cunit}<max{maxval}{maxunit}")
        except ValueError:
            below.append(f"{ftype}={cval}(unparse)")

    cur_str = ", ".join(shown[:6]) + (f" (+{len(shown)-6})" if len(shown) > 6 else "")
    if below:
        return "FAIL", (f"Current: {cur_str}. CIS 5.1 requires MAX "
                        f"-> below max: {', '.join(below[:6])}")
    return "PASS", f"Current (all at CIS max): {cur_str}"


def chk_5_4_wildfire_session_info(root):
    """
    CIS 5.4: All WildFire Session Information Settings enabled (Source/Dest IP+port,
    vsys, application, user, URL, filename, email sender/recipient/subject).
    All are ENABLED BY DEFAULT and only written to config when DISABLED.
    Logic: any session-info toggle explicitly 'no' = FAIL; else PASS.
    Path: deviceconfig/setting/wildfire/<toggle> = no
    """
    wf = root.find(".//deviceconfig/setting/wildfire")
    if wf is None:
        wf = root.find(".//setting/wildfire")

    disabled = []
    if wf is not None:
        for child in wf.iter():
            tag = child.tag
            txt = (child.text or "").strip().lower()
            if txt == "no" and (tag.startswith("report-")
                                or tag.startswith("send-")
                                or "session" in tag):
                disabled.append(tag)

    if disabled:
        return "FAIL", (f"Current: session-info options disabled: "
                        f"{', '.join(sorted(set(disabled)))}. CIS 5.4: enable all")
    return "PASS", ("Current: no session-info options disabled in config "
                    "(all enabled - CIS default). CIS 5.4 met")
