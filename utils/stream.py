import re


def first_sentence(text: str, max_len: int = 160) -> str:
    if not isinstance(text, str):
        text = str(text)
    # Split on sentence enders
    m = re.split(r"(?<=[.!?])\s+", text.strip())
    s = (m[0] if m else text).strip()
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def summarize_tool_run(run: dict) -> str:
    key = str(run.get("key", "tool")).strip()
    out = str(run.get("output", ""))
    cmd = str(run.get("cmd", ""))

    # curl headers
    if key.startswith("curl.") and (" -I " in cmd or " -I" in cmd or cmd.startswith("curl -I")):
        status = None
        server = None
        m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", out)
        if m:
            status = m.group(1)
        m = re.search(r"(?im)^server:\s*([^\r\n]+)", out)
        if m:
            server = m.group(1).strip()
        parts = []
        if status:
            parts.append(f"status {status}")
        if server:
            parts.append(f"server {server}")
        if parts:
            return f"Fetched HTTP headers; found {', '.join(parts)}."
        return "Fetched HTTP headers."

    # whatweb summary: pick technology tokens like Name[version]
    if key.startswith("whatweb."):
        techs = re.findall(r"([A-Za-z0-9_\-]+)\[([A-Za-z0-9_.:-]+)\]", out)
        if techs:
            top = ", ".join(f"{n} {v}" for n, v in techs[:6])
            return f"Identified technologies: {top}."
        return "Identified technologies (see evidence)."

    # nuclei: count matches + severities + CVEs
    if key.startswith("nuclei."):
        cves = len(re.findall(r"CVE-\d{4}-\d+", out, flags=re.I))
        sev = re.findall(r"(?i)severity[:=]\s*(critical|high|medium|low)", out)
        sev_counts = {}
        for s in sev:
            sev_counts[s.lower()] = sev_counts.get(s.lower(), 0) + 1
        parts = []
        if sev_counts:
            parts.append("; ".join(f"{k}:{v}" for k, v in sev_counts.items()))
        if cves:
            parts.append(f"CVEs:{cves}")
        return "Nuclei scan completed" + (" (" + ", ".join(parts) + ")" if parts else ".")

    # ffuf: count results and list distinct status codes
    if key.startswith("ffuf."):
        results = re.findall(r"Status:\s*(\d{3})", out)
        if results:
            from collections import Counter
            c = Counter(results)
            mix = ", ".join(f"{code}:{cnt}" for code, cnt in c.most_common())
            return f"ffuf discovered endpoints (status counts: {mix})."
        return "ffuf completed (no matches captured)."

    # sqlmap: vulnerable parameter messages
    if key.startswith("sqlmap."):
        if re.search(r"(?i)is vulnerable", out) or re.search(r"(?i)parameter\s+'?\w+'?\s+is\s+vulnerable", out):
            return "sqlmap reports injectable parameter(s)."
        return "sqlmap finished (see details)."

    # Generic fallback: first sentence of output
    return first_sentence(out)

