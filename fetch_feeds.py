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
                    "link": x.get("permalink") or x.get("post_url") or x.get("url") or ""})
    out.sort(key=lambda v: v["date"], reverse=True)
    return out[:limit]

SOURCES = {
    "kev": ("CISA KEV", kev),
    "c2": ("Feodo Tracker", feodo),
    "it_victims": ("ransomware.live (Italia)", lambda: victims("https://api.ransomware.live/v2/countryvictims/IT", 300)),
    "world_victims": ("ransomware.live (mondo)", lambda: victims("https://api.ransomware.live/v2/recentvictims", 100)),
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

data["generated"] = now
data["status"] = status
json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
print("OK", [(s["feed"], s["ok"]) for s in status])
