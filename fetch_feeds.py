python

import json, os, re, html, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

UA = {"User-Agent": "Mozilla/5.0 (ThreatIntelHub OSINT reader)"}
OUT = "data.json"


# ------------------------------------------------------------------ utilità
def get(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def clean(t):
    return html.unescape(re.sub(r"<[^>]+>", "", t or "")).strip()[:300]


def iso(s):
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc).isoformat()
    except Exception:
        return s or ""


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# ------------------------------------------------------------------ notizie
def rss(url, source, lang):
    root = ET.fromstring(get(url))
    out = []
    for it in root.iter("item"):
        out.append({"title": clean(it.findtext("title")),
                    "link": (it.findtext("link") or "").strip(),
                    "date": iso(it.findtext("pubDate")),
                    "summary": clean(it.findtext("description")),
                    "source": source, "lang": lang})
    if not out:  # Atom
        ns = "{http://www.w3.org/2005/Atom}"
        for e in root.iter(ns + "entry"):
            l = e.find(ns + "link")
            out.append({"title": clean(e.findtext(ns + "title")),
                        "link": l.get("href") if l is not None else "",
                        "date": e.findtext(ns + "updated") or "",
                        "summary": clean(e.findtext(ns + "summary")),
                        "source": source, "lang": lang})
    return out[:25]


def news_multi(items):
    """Scarica più feed RSS: se uno fallisce, gli altri vengono mantenuti."""
    out, errors = [], []
    for url, source, lang in items:
        try:
            out += rss(url, source, lang)
        except Exception as e:
            errors.append(f"{source}: {str(e)[:60]}")
    if not out and errors:
        raise RuntimeError("; ".join(errors))
    return out


# ------------------------------------------------------------------ feed tecnici
def kev():
    d = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    v = sorted(d["vulnerabilities"], key=lambda x: x["dateAdded"], reverse=True)[:150]
    return [{"cve": x["cveID"], "vendor": x["vendorProject"], "product": x["product"],
             "name": x["vulnerabilityName"], "added": x["dateAdded"],
             "due": x.get("dueDate", ""),
             "ransomware": x.get("knownRansomwareCampaignUse", "Unknown")} for x in v]


def feodo():
    d = json.loads(get("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    return [{"ip": x.get("ip_address"), "port": x.get("port"), "malware": x.get("malware"),
             "country": x.get("country"), "status": x.get("status"),
             "first_seen": x.get("first_seen"), "last_online": x.get("last_online")}
            for x in d][:300]


def victims(url, limit):
    d = json.loads(get(url))
    out = []
    for x in d:
        out.append({"victim": x.get("victim") or x.get("post_title") or "",
                    "group": x.get("group") or x.get("group_name") or "",
                    "country": x.get("country") or "",
                    "sector": x.get("activity") or "",
                    "date": x.get("discovered") or x.get("published") or "",
                    "site": x.get("website") or "",
                    "desc": clean(x.get("description")),
                    "link": x.get("permalink") or x.get("post_url") or x.get("url") or ""})
    out.sort(key=lambda v: v["date"], reverse=True)
    return out[:limit]


def groups():
    d = json.loads(get("https://api.ransomware.live/v2/groups"))
    out = {}
    known = {"name", "description", "profile", "locations"}
    for g in d:
        name = (g.get("name") or "").strip()
        if not name:
            continue
        prof = g.get("profile") or []
        extra = {k: str(v)[:200] for k, v in g.items()
                 if k not in known and isinstance(v, (str, int, float))
                 and v not in ("", None)}
        out[name.lower()] = {
            "name": name,
            "desc": clean(g.get("description") or ""),
            "profile": [p for p in prof if isinstance(p, str) and p.startswith("http")][:5],
            "sites": len(g.get("locations") or []),
            "extra": extra}
    return out


# ------------------------------------------------------------------ MISP Galaxy
GALAXY_URLS = [
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json",
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
]


def galaxy():
    """Restituisce {nome_minuscolo: {name, desc, synonyms, refs}} unendo i cluster."""
    out, errors = {}, []
    for url in GALAXY_URLS:
        try:
            d = json.loads(get(url, timeout=120))
        except Exception as e:
            errors.append(str(e)[:60])
            continue
        for v in d.get("values", []):
            name = (v..
