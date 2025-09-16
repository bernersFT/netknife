from typing import Any, Dict, List, Optional

import requests
import urllib3

from ..utils import (
    names, wrap_names, normalize_vip_payload
)

DEFAULT_TIMEOUT = 25  # seconds

class FortiGateClient:
    def __init__(self, host: str, token: str, vdom: Optional[str], verify_ssl: bool):
        self.token = token
        if not host.startswith(("http://", "https://")):
            host = "https://" + host
        self.base = host.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "X-Auth-Token": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        if not self.verify_ssl:
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    def _params(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {"access_token": self.token}
        if self.vdom:
            params["vdom"] = self.vdom
        if extra:
            params.update(extra)
        return params

    def _req(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, json_body: Optional[Any] = None):
        url = f"{self.base}{path}"
        r = self.session.request(
            method=method.upper(), url=url,
            params=self._params(params),
            json=json_body, timeout=DEFAULT_TIMEOUT,
            verify=self.verify_ssl
        )
        if not r.ok:
            raise RuntimeError(f"{method} {url} failed: {r.status_code} {r.text}")
        try:
            data = r.json()
        except Exception:
            return {}
        if isinstance(data, dict) and data.get("status") == "success" and "results" in data:
            data = data["results"]
        elif isinstance(data, dict) and "data" in data and data.get("status") == "success":
            data = data["data"]
        return data

    # -------- Policies
    def list_policies(self) -> List[Dict[str, Any]]:
        try:
            data = self._req("GET", "/api/v2/cmdb/firewall/policy")
        except RuntimeError as e:
            if " 424 " in str(e) and self.vdom is not None:
                vdom_keep = self.vdom; self.vdom = None
                try:
                    data = self._req("GET", "/api/v2/cmdb/firewall/policy")
                finally:
                    self.vdom = vdom_keep
            else:
                raise
        return data.get("results") if isinstance(data, dict) and "results" in data else (data if isinstance(data, list) else [])

    def get_policy_by_id(self, policy_id: int) -> Optional[Dict[str, Any]]:
        def _from_list(pol_list):
            try:
                pid = int(policy_id)
            except Exception:
                pid = policy_id
            for p in pol_list or []:
                try:
                    if int(p.get("policyid") or -1) == pid:
                        return p
                except Exception:
                    continue
            return None

        try:
            data = self._req("GET", f"/api/v2/cmdb/firewall/policy/{policy_id}")
        except RuntimeError:
            return _from_list(self.list_policies())

        if isinstance(data, dict):
            if "policyid" in data:
                return data
            if "results" in data:
                res = data["results"]
                if isinstance(res, dict) and "policyid" in res:
                    return res
                if isinstance(res, list) and res:
                    got = _from_list(res)
                    if got:
                        return got
                return _from_list(self.list_policies())
            return _from_list(self.list_policies())

        if isinstance(data, list):
            got = _from_list(data)
            if got:
                return got
            return _from_list(self.list_policies())

        return _from_list(self.list_policies())

    def get_policy_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for p in self.list_policies():
            if str(p.get("name") or "").strip() == str(name).strip():
                return p
        return None

    def create_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._req("POST", "/api/v2/cmdb/firewall/policy", json_body=payload)
        if "name" in payload:
            got = self.get_policy_by_name(payload["name"])
            if got: return got
        return payload

    def update_policy(self, policy_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=payload)
        return self.get_policy_by_id(policy_id) or {"policyid": policy_id, **payload}

    def update_policy_addrs(self, policy_id: int, *, add_src=None, add_dst=None, remove_src=None, remove_dst=None) -> Dict[str, Any]:
        add_src = add_src or []
        add_dst = add_dst or []
        remove_src = remove_src or []
        remove_dst = remove_dst or []

        p = self.get_policy_by_id(policy_id)
        if not p:
            raise RuntimeError(f"Policy {policy_id} not found")

        def _to_names(lst):
            out = set()
            for x in lst or []:
                if isinstance(x, dict):
                    n = x.get("name")
                else:
                    n = x
                if n:
                    out.add(str(n))
            return out

        cur_src = _to_names(p.get("srcaddr"))
        cur_dst = _to_names(p.get("dstaddr"))

        new_src = sorted((cur_src | set(add_src)) - set(remove_src))
        new_dst = sorted((cur_dst | set(add_dst)) - set(remove_dst))

        if "all" in new_src and len(new_src) > 1:
            new_src = [n for n in new_src if n != "all"]
        if "all" in new_dst and len(new_dst) > 1:
            new_dst = [n for n in new_dst if n != "all"]

        body_light = {"srcaddr": [{"name": n} for n in new_src],
                      "dstaddr": [{"name": n} for n in new_dst]}
        try:
            self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=body_light)
            return self.get_policy_by_id(policy_id)
        except RuntimeError as e:
            msg = str(e)
            if ('"http_status":500' in msg and ('"error":-7' in msg or '"error": -7' in msg)) or ' 424 ' in msg:
                pass
            else:
                raise

        keep_keys = {
            "name", "status", "action", "srcintf", "dstintf", "service",
            "schedule", "nat", "logtraffic",
            "ips-sensor", "av-profile", "webfilter-profile", "application-list", "ssl-ssh-profile",
            "comments", "comment"
        }
        body_full: Dict[str, Any] = {}
        for k, v in (p or {}).items():
            if k in keep_keys and v is not None:
                body_full[k] = v
        body_full["srcaddr"] = [{"name": n} for n in new_src]
        body_full["dstaddr"] = [{"name": n} for n in new_dst]

        self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=body_full)
        return self.get_policy_by_id(policy_id)

    # -------- Addresses
    def list_addresses(self) -> List[Dict[str, Any]]:
        try:
            data = self._req("GET", "/api/v2/cmdb/firewall/address")
        except RuntimeError as e:
            if " 424 " in str(e) and self.vdom is not None:
                vdom_keep = self.vdom; self.vdom = None
                try:
                    data = self._req("GET", "/api/v2/cmdb/firewall/address")
                finally:
                    self.vdom = vdom_keep
            else:
                raise
        return data.get("results") if isinstance(data, dict) and "results" in data else (data if isinstance(data, list) else [])

    def get_address(self, name: str) -> Optional[Dict[str, Any]]:
        from urllib.parse import quote as url_quote
        try:
            data = self._req("GET", f"/api/v2/cmdb/firewall/address/{url_quote(name, safe='')}")
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        for a in self.list_addresses():
            if str(a.get("name") or "") == str(name):
                return a
        return None

    def create_address(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            self._req("POST", "/api/v2/cmdb/firewall/address", json_body=payload)
        except RuntimeError as e:
            msg = str(e)
            if '"http_status":500' in msg and ('"error":-5' in msg or '"error": -5' in msg):
                p2 = dict(payload)
                if isinstance(p2.get("subnet"), str) and " " in p2["subnet"]:
                    ip, mask = p2["subnet"].split(" ", 1)
                    p2["subnet"] = [ip.strip(), mask.strip()]
                elif isinstance(p2.get("subnet"), list) and len(p2["subnet"]) == 2:
                    p2["subnet"] = f"{p2['subnet'][0]} {p2['subnet'][1]}"
                self._req("POST", "/api/v2/cmdb/firewall/address", json_body=p2)
                return self.get_address(p2["name"]) or p2
            raise
        return self.get_address(payload["name"]) or payload

    def update_address(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import quote as url_quote
        self._req("PUT", f"/api/v2/cmdb/firewall/address/{url_quote(name, safe='')}", json_body=payload)
        return self.get_address(name) or {"name": name, **payload}

    def delete_address(self, name: str) -> None:
        from urllib.parse import quote as url_quote
        self._req("DELETE", f"/api/v2/cmdb/firewall/address/{url_quote(name, safe='')}")

    # -------- Address-Groups
    def list_addrgrps(self) -> List[Dict[str, Any]]:
        try:
            data = self._req("GET", "/api/v2/cmdb/firewall/addrgrp")
        except RuntimeError as e:
            if " 424 " in str(e) and self.vdom is not None:
                vdom_keep = self.vdom; self.vdom = None
                try:
                    data = self._req("GET", "/api/v2/cmdb/firewall/addrgrp")
                finally:
                    self.vdom = vdom_keep
            else:
                raise
        return data.get("results") if isinstance(data, dict) and "results" in data else (data if isinstance(data, list) else [])

    def get_addrgrp(self, name: str) -> Optional[Dict[str, Any]]:
        from urllib.parse import quote as url_quote
        try:
            data = self._req("GET", f"/api/v2/cmdb/firewall/addrgrp/{url_quote(name, safe='')}")
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        for g in self.list_addrgrps():
            if str(g.get("name") or "") == str(name):
                return g
        return None

    def create_addrgrp(self, name: str, members: Optional[List[str]] = None, comment: Optional[str] = None, **extra) -> Dict[str, Any]:
        body: Dict[str, Any] = {"name": name}
        if comment:
            body["comment"] = comment
        if members:
            body["member"] = wrap_names(members)
        body.update(extra or {})
        self._req("POST", "/api/v2/cmdb/firewall/addrgrp", json_body=body)
        return self.get_addrgrp(name) or body

    def update_addrgrp(self, name: str, *, new_name: Optional[str] = None, members: Optional[List[str]] = None, comment: Optional[str] = None, **extra) -> Dict[str, Any]:
        from urllib.parse import quote as url_quote
        body: Dict[str, Any] = {}
        if new_name:
            body["name"] = new_name
        if comment is not None:
            body["comment"] = comment
        if members is not None:
            body["member"] = wrap_names(members)
        if extra:
            body.update(extra)
        self._req("PUT", f"/api/v2/cmdb/firewall/addrgrp/{url_quote(name, safe='')}", json_body=body)
        return self.get_addrgrp(new_name or name) or {"name": new_name or name, **body}

    def delete_addrgrp(self, name: str) -> None:
        from urllib.parse import quote as url_quote
        self._req("DELETE", f"/api/v2/cmdb/firewall/addrgrp/{url_quote(name, safe='')}")

    def add_members_to_addrgrp(self, name: str, to_add: List[str]) -> Dict[str, Any]:
        grp = self.get_addrgrp(name)
        if not grp:
            raise RuntimeError(f"Address-Group '{name}' not found")
        current = set(names(grp.get("member")))
        merged = sorted(current.union(set(to_add)))
        return self.update_addrgrp(name, members=merged)

    def remove_members_from_addrgrp(self, name: str, to_remove: List[str]) -> Dict[str, Any]:
        grp = self.get_addrgrp(name)
        if not grp:
            raise RuntimeError(f"Address-Group '{name}' not found")
        current = set(names(grp.get("member")))
        merged = sorted(current.difference(set(to_remove)))
        return self.update_addrgrp(name, members=merged)

    def object_exists(self, name: str) -> bool:
        try:
            a = self.get_address(name)
            if a: return True
        except Exception:
            pass
        try:
            g = self.get_addrgrp(name)
            if g: return True
        except Exception:
            pass
        return False

    # -------- VIPs
    def list_vips(self) -> List[Dict[str, Any]]:
        try:
            data = self._req("GET", "/api/v2/cmdb/firewall/vip")
        except RuntimeError as e:
            if " 424 " in str(e) and self.vdom is not None:
                vdom_keep = self.vdom; self.vdom = None
                try:
                    data = self._req("GET", "/api/v2/cmdb/firewall/vip")
                finally:
                    self.vdom = vdom_keep
            else:
                raise
        return data.get("results") if isinstance(data, dict) and "results" in data else (data if isinstance(data, list) else [])

    def get_vip(self, name: str) -> Optional[Dict[str, Any]]:
        from urllib.parse import quote as url_quote
        try:
            data = self._req("GET", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}")
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        for v in self.list_vips():
            if str(v.get("name") or "") == str(name):
                return v
        return None

    def create_vip(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        p0 = normalize_vip_payload(payload)
        try:
            self._req("POST", "/api/v2/cmdb/firewall/vip", json_body=p0)
            return self.get_vip(p0.get("name")) or p0
        except RuntimeError:
            pass

        alt_shapes = []
        mi = payload.get("mappedip")
        if isinstance(mi, list):
            alt_shapes.append(list(mi))
            if len(mi) == 1:
                alt_shapes.append(mi[0])
        elif isinstance(mi, str):
            alt_shapes.append([mi])

        for shape in alt_shapes:
            p2 = normalize_vip_payload(dict(payload))
            p2["mappedip"] = shape
            try:
                self._req("POST", "/api/v2/cmdb/firewall/vip", json_body=p2)
                return self.get_vip(p2.get("name")) or p2
            except RuntimeError:
                continue

        raise

    def update_vip(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import quote as url_quote
        p0 = normalize_vip_payload(payload)
        try:
            self._req("PUT", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}", json_body=p0)
            return self.get_vip(name) or p0
        except RuntimeError:
            pass

        alt_shapes = []
        mi = payload.get("mappedip")
        if isinstance(mi, list):
            alt_shapes.append(list(mi))
            if len(mi) == 1:
                alt_shapes.append(mi[0])
        elif isinstance(mi, str):
            alt_shapes.append([mi])

        for shape in alt_shapes:
            p2 = normalize_vip_payload(dict(payload))
            p2["mappedip"] = shape
            try:
                self._req("PUT", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}", json_body=p2)
                return self.get_vip(name) or p2
            except RuntimeError:
                continue

        raise

    def delete_vip(self, name: str) -> None:
        from urllib.parse import quote as url_quote
        self._req("DELETE", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}")

