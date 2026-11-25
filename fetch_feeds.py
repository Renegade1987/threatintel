import json, os, re, html, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept": "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
      "Accept-Language": "it-IT,it;q=0.9,en;q=0.8"}
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

def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())

def rss(url, source, lang):
    raw = get(url).lstrip(b"\xef\xbb\xbf \r\n\t")
    if not raw.startswith(b"<"):
        raise ValueError("risposta non XML: " + raw[:60].decode("utf-8", "replace"))
    root = ET.fromstring(raw)
    out = []
    for it in root.iter("item"):
        out.append({"title": clean(it.findtext("title")), "link": (it.findtext("link") or "").strip(),
                    "date": iso(it.findtext("pubDate")), "summary": clean(it.findtext("description")),
                    "source": source, "lang": lang})
    if not out:
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
    out, errors = [], []
    for urls, source, lang in items:
        last = ""
        for url in urls:
            try:
                out += rss(url, source, lang)
                last = ""
                break
            except Exception as e:
                last = str(e)[:80]
        if last:
            errors.append(source + ": " + last)
    if not out and errors:
        raise RuntimeError(" | ".join(errors))
    return out

def kev():
    d = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    v = sorted(d["vulnerabilities"], key=lambda x: x["dateAdded"], reverse=True)[:150]
    return [{"cve": x["cveID"], "vendor": x["vendorProject"], "product": x["product"],
             "name": x["vulnerabilityName"], "added": x["dateAdded"], "due": x.get("dueDate", ""),
             "ransomware": x.get("knownRansomwareCampaignUse", "Unknown")} for x in v]

def feodo():
    d = json.loads(get("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    return [{"ip": x.get("ip_address"), "port": x.get("port"), "malware": x.get("malware"),
             "country": x.get("country"), "status": x.get("status"),
             "first_seen": x.get("first_seen"), "last_online": x.get("last_online")} for x in d][:300]

def victims(url, limit):
    d = json.loads(get(url))
    out = []
    for x in d:
        out.append({"victim": x.get("victim") or x.get("post_title") or "",
                    "group": x.get("group") or x.get("group_name") or "",
                    "country": x.get("country") or "", "sector": x.get("activity") or "",
                    "date": x.get("discovered") or x.get("published") or "",
                    "site": x.get("website") or "", "desc": clean(x.get("description")),
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
                 if k not in known and isinstance(v, (str, int, float)) and v not in ("", None)}
        out[name.lower()] = {"name": name, "desc": clean(g.get("description") or ""),
                             "profile": [p for p in prof if isinstance(p, str) and p.startswith("http")][:5],
                             "sites": len(g.get("locations") or []), "extra": extra}
    return out

GALAXY_URLS = [
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json",
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"]

def galaxy():
    out, errors = {}, []
    for url in GALAXY_URLS:
        try:
            d = json.loads(get(url, timeout=120))
        except Exception as e:
            errors.append(str(e)[:60])
            continue
        for v in d.get("values", []):
            name = (v.get("value") or "").strip()
            if not name:
                continue
            meta = v.get("meta") or {}
            syn = [s for s in (meta.get("synonyms") or []) if isinstance(s, str)][:15]
            refs = [r for r in (meta.get("refs") or []) if isinstance(r, str) and r.startswith("http")][:5]
            key = name.lower()
            cur = out.get(key)
            if cur:
                cur["synonyms"] = list(dict.fromkeys(cur["synonyms"] + syn))[:20]
                cur["refs"] = list(dict.fromkeys(cur["refs"] + refs))[:6]
                if not cur["desc"]:
                    cur["desc"] = clean(v.get("description") or "")
            else:
                out[key] = {"name": name, "desc": clean(v.get("description") or ""),
                            "synonyms": syn, "refs": refs}
    if not out:
        raise RuntimeError("; ".join(errors) or "nessun dato Galaxy")
    return out

def alias_index(gal):
    idx = {}
    for g in gal.values():
        names = {norm(g["name"])} | {norm(s) for s in g["synonyms"]}
        names.discard("")
        for n in names:
            idx.setdefault(n, set()).update(names)
    return idx

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ALIASES = {
    "alphv": ["blackcat"], "blackcat": ["alphv"],
    "revil": ["sodinokibi"], "sodinokibi": ["revil"],
    "blackmatter": ["darkside"], "darkside": ["blackmatter"],
    "royal": ["blacksuit"], "blacksuit": ["royal"],
    "wizardspider": ["conti", "ryuk"], "conti": ["wizardspider"],
    "lockbit": ["lockbit20", "lockbit30"],
    "evilcorp": ["indrik", "dridex"]}

def mitre(wanted, aidx):
    objs = json.loads(get(MITRE_URL, timeout=180))["objects"]
    live = {o["id"]: o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    patterns = {i: o for i, o in live.items() if o["type"] == "attack-pattern"}
    index = {}
    for o in live.values():
        if o["type"] in ("intrusion-set", "malware", "tool"):
            for n in [o["name"]] + o.get("aliases", []) + o.get("x_mitre_aliases", []):
                index.setdefault(norm(n), {})[o["id"]] = o
    uses, sw_used = {}, {}
    for r in live.values():
        if r["type"] != "relationship" or r.get("relationship_type") != "uses":
            continue
        s, t = r["source_ref"], r["target_ref"]
        if t in patterns:
            uses.setdefault(s, set()).add(t)
        elif t in live and live[t]["type"] in ("malware", "tool") and s in live and live[s]["type"] == "intrusion-set":
            sw_used.setdefault(s, set()).add(t)

    def ext(o):
        for e in o.get("external_references", []):
            if e.get("source_name") == "mitre-attack":
                return e.get("external_id", ""), e.get("url", "")
        return "", ""

    def find(k):
        c = dict(index.get(k) or {})
        if not c:
            c = dict(index.get(re.sub(r"\d+$", "", k)) or {})
        if not c and len(k) >= 5:
            for name, objs_ in index.items():
                if name.startswith(k):
                    c.update(objs_)
        return c

    out = {}
    for w in wanted:
        k = norm(w)
        if len(k) < 3:
            continue
        cands = find(k)
        alias = set(ALIASES.get(k, [])) | set(aidx.get(k, set()))
        alias.discard(k)
        for a in alias:
            if len(a) >= 3:
                cands.update(index.get(a) or {})
        res = []
        for o in list(cands.values())[:4]:
            ids = set(uses.get(o["id"], []))
            if o["type"] == "intrusion-set":
                for sid in sw_used.get(o["id"], []):
                    ids |= uses.get(sid, set())
            tech = []
            for pid in ids:
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

old = {}
if os.path.exists(OUT):
    try:
        old = json.load(open(OUT, encoding="utf-8"))
    except Exception:
        old = {}

now = datetime.now(timezone.utc).isoformat()
data, status = {}, []

def run(key, label, fn, default):
    try:
        data[key] = fn()
        status.append({"feed": label, "ok": True, "count": len(data[key]), "updated": now, "error": ""})
    except Exception as e:
        data[key] = old.get(key, default)
        prev = next((s for s in old.get("status", []) if s["feed"] == label), {})
        status.append({"feed": label, "ok": False, "count": len(data[key]),
                       "updated": prev.get("updated", ""), "error": str(e)[:400]})

run("kev", "CISA KEV", kev, [])
run("c2", "Feodo Tracker", feodo, [])
run("it_victims", "ransomware.live (Italia)", lambda: victims("https://api.ransomware.live/v2/countryvictims/IT", 300), [])
run("world_victims", "ransomware.live (mondo)", lambda: victims("https://api.ransomware.live/v2/recentvictims", 100), [])
run("groups", "ransomware.live (gruppi)", groups, {})
run("news_it", "Notizie IT", lambda: news_multi([
    (["https://www.redhotcyber.com/feed/",
      "https://news.google.com/rss/search?q=site:redhotcyber.com&hl=it&gl=IT&ceid=IT:it"], "Red Hot Cyber", "it"),
    (["https://www.cybersecurity360.it/feed/",
      "https://news.google.com/rss/search?q=site:cybersecurity360.it&hl=it&gl=IT&ceid=IT:it"], "Cybersecurity360", "it")]), [])
run("news_en", "Notizie EN", lambda: news_multi([
    (["https://www.bleepingcomputer.com/feed/"], "BleepingComputer", "en"),
    (["https://feeds.feedburner.com/securityweek"], "SecurityWeek", "en"),
    (["https://therecord.media/feed"], "The Record", "en"),
    (["https://feeds.feedburner.com/TheHackersNews"], "The Hacker News", "en")]), [])
run("galaxy", "MISP Galaxy", galaxy, {})

for n in ("news_it", "news_en"):
    data[n].sort(key=lambda x: x.get("date", ""), reverse=True)

gal = data.get("galaxy") or {}
aidx = alias_index(gal)
gmap = {}
for g in gal.values():
    gmap[norm(g["name"])] = g
    for s in g["synonyms"]:
        gmap.setdefault(norm(s), g)
for key, info in (data.get("groups") or {}).items():
    g = gmap.get(norm(info.get("name", key)))
    if not g:
        continue
    if not info.get("desc"):
        info["desc"] = g["desc"]
    if g["synonyms"]:
        info.setdefault("extra", {})["alias (MISP Galaxy)"] = ", ".join(g["synonyms"][:8])
    info["profile"] = list(dict.fromkeys((info.get("profile") or []) + g["refs"]))[:6]

wanted = {g["name"] for g in (data.get("groups") or {}).values()}
for key in ("it_victims", "world_victims"):
    wanted |= {v["group"] for v in data.get(key, []) if v.get("group")}
run("mitre", "MITRE ATT&CK", lambda: mitre(wanted, aidx), {})

data["generated"] = now
data["status"] = status
json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
print("OK", [(s["feed"], s["ok"]) for s in status])
