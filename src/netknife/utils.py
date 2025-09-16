import json
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

def print_json(obj: Any):
    print(json.dumps(obj, ensure_ascii=False, indent=2))

def names(list_or_none: Optional[List[Any]]) -> List[str]:
    lst = list_or_none or []
    out: List[str] = []
    for x in lst:
        if isinstance(x, dict):
            n = x.get("name")
            if n is not None:
                out.append(str(n))
        else:
            out.append(str(x))
    return out

def wrap_names(names_iter: Iterable[str]) -> List[Dict[str, str]]:
    return [{"name": str(n)} for n in names_iter]

def load_json_arg(s: Optional[str]):

    if s is None:
        return None
    s = s.strip()
    if s.startswith("@"):
        path = s[1:]
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        s2 = s
        if s2.startswith("'") and s2.endswith("'"):
            s2 = s2[1:-1]
        s2 = s2.replace("'", '"')
        return json.loads(s2)

def cidr_to_subnet_str(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    return f"{net.network_address} {net.netmask}"

def suggest_similar(target: str, pool: List[str], limit: int = 8) -> List[str]:
    t = (target or "").lower()
    def score(name):
        n = (name or "").lower()
        if n == t: return 100
        if n.startswith(t): return 80
        if t in n: return 60
        common = len(set(n.replace('-', '').replace('_','')) & set(t.replace('-', '').replace('_','')))
        return common
    scored = sorted(pool, key=lambda n: score(n), reverse=True)
    out, seen = [], set()
    for n in scored:
        k = (n or "").lower()
        if k in seen: continue
        if len(out) >= limit: break
        if score(n) > 0:
            out.append(n); seen.add(k)
    return out

def to_enable_disable(val: Any) -> str:
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("enable", "disable"):
            return v
        if v in ("true", "yes", "1"):
            return "enable"
        if v in ("false", "no", "0"):
            return "disable"
    return "enable" if bool(val) else "disable"

def normalize_vip_payload(payload: Dict[str, Any]) -> Dict[str, Any]:

    p = dict(payload or {})
    extip = p.get("extip")
    if isinstance(extip, str) and "/" in extip:
        try:
            net = ipaddress.ip_network(extip, strict=False)
            p["extip"] = str(net.network_address)
        except Exception:
            pass

    def _to_range_list(val):
        if val is None:
            return None
        if isinstance(val, list):
            out = []
            for x in val:
                if isinstance(x, dict) and "range" in x:
                    out.append({"range": str(x["range"])})
                else:
                    out.append({"range": str(x)})
            return out
        else:
            return [{"range": str(val)}]

    mi = p.get("mappedip")
    if mi is not None:
        p["mappedip"] = _to_range_list(mi)

    if "portforward" in p:
        p["portforward"] = to_enable_disable(p["portforward"])

    if "extport" in p and p["extport"] is not None:
        p["extport"] = str(p["extport"])
    if "mappedport" in p and p["mappedport"] is not None:
        p["mappedport"] = str(p["mappedport"])

    p.setdefault("type", "static-nat")
    return p

def address_brief(addr: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(addr, dict):
        return {"name": str(addr)}
    t = addr.get("type") or "ipmask"
    brief: Dict[str, Any] = {"name": addr.get("name"), "type": t, "comment": addr.get("comment"), "uuid": addr.get("uuid")}
    if t == "ipmask":
        subnet = addr.get("subnet")
        if isinstance(subnet, list) and len(subnet) == 2:
            brief["value"] = f"{subnet[0]}/{subnet[1]}"
        else:
            brief["value"] = subnet
    elif t == "iprange":
        brief["value"] = f"{addr.get('start-ip')} - {addr.get('end-ip')}"
    elif t == "fqdn":
        brief["value"] = addr.get("fqdn")
    elif t == "geography":
        brief["value"] = addr.get("country")
    elif t == "wildcard":
        brief["value"] = f"{addr.get('wildcard')} / {addr.get('wildcard-fmask')}"
    else:
        for k in ("subnet", "start-ip", "end-ip", "fqdn", "country", "wildcard"):
            if addr.get(k):
                brief["value"] = addr.get(k); break
    return brief

def pick_policy_fields(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "policyid": p.get("policyid"),
        "name": p.get("name"),
        "uuid": p.get("uuid"),
        "status": p.get("status"),
        "action": p.get("action"),
        "srcintf": names(p.get("srcintf")),
        "dstintf": names(p.get("dstintf")),
        "srcaddr": names(p.get("srcaddr")),
        "dstaddr": names(p.get("dstaddr")),
        "service": names(p.get("service")),
        "schedule": p.get("schedule"),
        "nat": p.get("nat"),
        "logtraffic": p.get("logtraffic"),
        "comments": p.get("comments") or p.get("comment"),
        "utm": {
            "ips": p.get("ips-sensor"),
            "av": p.get("av-profile"),
            "webfilter": p.get("webfilter-profile"),
            "appctrl": p.get("application-list"),
            "ssl_ssh_profile": p.get("ssl-ssh-profile"),
        }
    }

def vip_brief(v: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(v, dict):
        return {"name": str(v)}
    return {
        "name": v.get("name"),
        "uuid": v.get("uuid"),
        "extintf": v.get("extintf"),
        "extip": v.get("extip"),
        "mappedip": v.get("mappedip"),
        "portforward": v.get("portforward"),
        "protocol": v.get("protocol"),
        "extport": v.get("extport"),
        "mappedport": v.get("mappedport"),
        "comment": v.get("comment"),
        "type": v.get("type"),
    }

def match_base_groups(all_groups: List[Dict[str, Any]], base: str) -> List[Tuple[str, int]]:
    exact: List[Tuple[str, int]] = []
    pat = re.compile(rf"^{re.escape(base)}(?:-(\d+))?$")
    for g in all_groups:
        name = g.get("name") or ""
        m = pat.match(name)
        if m:
            idx = int(m.group(1)) if m.group(1) else 1
            exact.append((name, idx))
    exact.sort(key=lambda x: x[1])
    return exact

