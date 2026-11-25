import json, os, re, html, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

UA = {"User-Agent": "Mozilla/5.0 (ThreatIntelHub OSINT reader)"}
OUT = "data.json"

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

def rss(url, source, lang):
    root = ET.fromstring(get(url))
    out = []
    for it in root.iter("item"):
        out.append({"title": clean(it.findtext("title")), "link": (it.findtext("link") or "").strip(),
                    "date": iso(it.findtext("pubDate")), "summary": clean(it.findtext("description")),
                    "source": source, "lang": lang})
    if not out:  # Atom
        ns = "{http://www.w3.org/2005/Atom}"
        for e in root.iter(ns + "entry"):
            l = e.find(ns + "link")
            out.append({"title": clean(e.findtext(ns + "title")), "link": l.get("href") if l is not None else "",
                        "date": e.findtext(ns + "updated") or "", "summary": clean(e.findtext(ns + "summary")),
                        "source": source, "lang": lang})
    return out[:25]

def kev():
    d = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    v = sorted(d["vulnerabilities"], key=lambda x: x["dateAdded"], reverse=True)[:150]
    return [{"cve": x["cveID"], "vendor": x["vendorProject"], "product": x["product"], "name": x["vulnerabilityName"],
             "added": x["dateAdded"], "due": x.get("dueDate", ""),
             "ransomware": x.get("knownRansomwareCampaignUse", "Unknown")} for x in v]

def feodo():
    d = json.loads(get("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    return [{"ip": x.get("ip_address"), "port": x.get("port"), "malware": x.get("malware"),
             "country": x.get("country"), "status": x.get("status"), "first_seen": x.get("first_seen"),
             "last_online": x.get("last_online")} for x in d][:300]

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
                    "desc": clean(x.get("description"))[:300],
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
    MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())

def mitre(wanted):
    objs = json.loads(get(MITRE_URL, timeout=180))["objects"]
    live = {o["id"]: o for o in objs
            if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    patterns = {i: o for i, o in live.items() if o["type"] == "attack-pattern"}
    index = {}
    for o in live.values():
        if o["type"] in ("intrusion-set", "malware", "tool"):
            names = [o["name"]] + o.get("aliases", []) + o.get("x_mitre_aliases", [])
            for n in names:
                index.setdefault(norm(n), {})[o["id"]] = o
    uses = {}
    for r in live.values():
        if r["type"] == "relationship" and r.get("relationship_type") == "uses" \
           and r["target_ref"] in patterns:
            uses.setdefault(r["source_ref"], set()).add(r["target_ref"])

    def ext(o):
        for e in o.get("external_references", []):
            if e.get("source_name") == "mitre-attack":
                return e.get("external_id", ""), e.get("url", "")
        return "", ""

    out = {}
    for w in wanted:
        k = norm(w)
        if len(k) < 3:
            continue
        cands = index.get(k) or index.get(re.sub(r"\d+$", "", k)) or {}
        res = []
        for o in list(cands.values())[:3]:
            tech = []
            for pid in uses.get(o["id"], []):
                p = patterns[pid]
                tid, url = ext(p)
                tech.append({"id": tid, "name": p["name"], "url": url,
                             "tactics": [kc["phase_name"] for kc in p.get("kill_chain_phases", [])]})
            tech.sort(key=lambda t: t["id"])
            eid, eurl = ext(o)
            res.append({"name": o["name"], "id": eid, "url": eurl,
                        "type": "Gruppo" if o["type"] == "intrusion-set" else "Software",
                        "techniques": tech})
        if res:
            out[w.lower()] = res
    return out
SOURCES = {
    "kev": ("CISA KEV", kev),
    "c2": ("Feodo Tracker", feodo),
    "it_victims": ("ransomware.live (Italia)", lambda: victims("https://api.ransomware.live/v2/countryvictims/IT", 300)),
    "world_victims": ("ransomware.live (mondo)", lambda: victims("https://api.ransomware.live/v2/recentvictims", 100)),
    "groups": ("ransomware.live (gruppi)", groups),
    "news_it": ("Notizie IT", lambda: sum([
        rss("https://www.redhotcyber.com/feed/", "Red Hot Cyber", "it"),
        rss("https://www.cybersecurity360.it/feed/", "Cybersecurity360", "it")], [])),
    "news_en": ("Notizie EN", lambda: sum([
        rss("https://www.bleepingcomputer.com/feed/", "BleepingComputer", "en"),
        rss("https://feeds.feedburner.com/securityweek", "SecurityWeek", "en"),
        rss("https://therecord.media/feed", "The Record", "en"),
        rss("https://feeds.feedburner.com/TheHackersNews", "The Hacker News", "en")], [])),
}

old = {}
if os.path.exists(OUT):
    try: old = json.load(open(OUT, encoding="utf-8"))
    except Exception: pass

now = datetime.now(timezone.utc).isoformat()
data, status = {}, []
for key, (label, fn) in SOURCES.items():
    try:
        data[key] = fn()
        status.append({"feed": label, "ok": True, "count": len(data[key]), "updated": now, "error": ""})
    except Exception as e:
        data[key] = old.get(key, [])
        prev = next((s for s in old.get("status", []) if s["feed"] == label), {})
        status.append({"feed": label, "ok": False, "count": len(data[key]),
                       "updated": prev.get("updated", ""), "error": str(e)[:120]})

for n in ("news_it", "news_en"):
    data[n].sort(key=lambda x: x["date"], reverse=True)
try:
    wanted = {g["name"] for g in (data.get("groups") or {}).values()}
    for key in ("it_victims", "world_victims"):
        wanted |= {v["group"] for v in data.get(key, []) if v.get("group")}
    data["mitre"] = mitre(wanted)
    status.append({"feed": "MITRE ATT&CK", "ok": True, "count": len(data["mitre"]),
                   "updated": now, "error": ""})
except Exception as e:
    data["mitre"] = old.get("mitre", {})
    prev = next((s for s in old.get("status", []) if s["feed"] == "MITRE ATT&CK"), {})
    status.append({"feed": "MITRE ATT&CK", "ok": False, "count": len(data["mitre"]),
                   "updated": prev.get("updated", ""), "error": str(e)[:120]})
data["generated"] = now
data["status"] = status
json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
print("OK", [(s["feed"], s["ok"]) for s in status])
