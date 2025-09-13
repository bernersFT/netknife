#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 用法
# python fortigate_inspector-6.py --host https://10.146.250.254:10443 --token 8x75nxfn4HjzNfy8k1thhq88g5GnH9 (--vdom SL-Internet) --insecure
# 查看 地址组与地址 在策略中的调用关系
#  find-policies-with --object-name "Blacklist_from_ELK"

# 获取 地址列表 信息
# list-addresses

# 删除 单个地址
# delete-address --name "210.57.33.162"

# 获取 单个地址 详细信息
# get-address --name "crl.pki.goog"

# 更新 单个地址
# update-address --name "BAN-77.90.151.5" --data "{'comment':'updated'}"

#创建 单个地址
# create-address-ipmask --name "A-10.0.0.0_24" --cidr 10.0.0.0/24
#================策略相关==================
#获取 具体权限信息 基于策略名称    
# policy-name --policy-name "黑名单-入方向"

# 创建策略
# python fortigate_inspector-7.py --host ... --token <TOKEN> --vdom SL-Internet --insecure ^
#   create-policy-simple ^
#   --name "黑名单-入方向-副本" ^
#   --srcintf "any" ^
#   --dstintf "any" ^
#   --srcaddr "blacklist-must-deny,blacklist-auto,Blacklist_from_ELK" ^
#   --dstaddr "all" ^
#   --service "ALL" ^
#   --action deny ^
#   --schedule always ^
#   --status enable ^
#   --logtraffic all ^
#   --comment "created by script"


#更新策略 基于ID
#   update-policy-fields --policy-id 263 ^
#   --srcaddr "Blacklist_from_ELK,Code_Group_BlackList" ^
#   --dstaddr "all" ^
#   --logtraffic all ^
#   --comment "updated by script"

#停用策略 基于ID
#   update-policy-fields --policy-id 263 --status edisable

# 移除/增加策略用的 src/dst 对象； 不兼容值为‘all’的策略
# policy-set-addrs --policy-id 263 --remove-src "Blacklist_from_ELK"
# policy-set-addrs --policy-id 263 --add-dst "Blacklist_from_ELK"

# 基于地址组基本名称批量添加所有地址组到策略
# attach-grps-to-policy --policy-id 263 --base-name "Blacklist_from_ELK" --direction dst

# =============对地址组的操作默认会校验成员存在，若想跳过可加 --skip-validate-members============
# 修改 地址组 名称
# update-addrgrp --name "HQ-NETWORKS" --new-name "HQ-NETWORKS-NEW"

# 追加 地址 到 地址组
# add-to-addrgrp --name "HQ-NETWORKS" --members "10.145.6.0/23"

# 移除 地址 从 地址组
# remove-from-addrgrp --name "HQ-NETWORKS" --members "10.145.6.0/23"

# 更新 地址组 ， 是全部替换，不是追加
# update-addrgrp --name "HQ-NETWORKS" --members "A-10.0.0.0_24,Another-Addr" --comment "updated"

# 获取 当个地址组 详细信息
# get-addrgrp --name "Blacklist_from_ELK"

# 创建 地址组 可选参数：--member
# create-addrgrp --name "HQ-NETWORKS" --members "BAN-131.226.102.110,BAN-136.158.27.158" --comment "demo"

# 255分片添加地址到地址组，即超过255后，会新建组
# smart-fill-addrgrps --base-name "Blacklist_from_ELK" --members "A-10.0.0.0_24,HQ-NETWORKS" --chunk-size 255

"""
FortiGate Policy & Address Toolkit
- 兼容 header + ?access_token=token
- 支持 --insecure 抑制告警；对 7.x 的 424 做兜底
- 功能要点：
  * 策略：按 ID/名称查看、搜索、创建、更新、快捷增删 srcaddr/dstaddr
  * 地址：CRUD、检索、免 JSON 创建/改备注
  * 地址组：CRUD、检索、更新（覆盖/改名/改备注）、追加/移除成员、找成员所在组
  * 智能分片：每组 ≤N(默认255)，自动建 “-2/-3/…”
  * 一键 attach：把 base 及其 “-N” 全挂到策略 src/dst
  * probe：monitor+cmdb 自检
"""

import argparse
import json
import sys
import re
from typing import Dict, List, Optional, Any, Iterable, Tuple
from urllib.parse import quote as url_quote

import requests
import urllib3
import ipaddress

DEFAULT_TIMEOUT = 25  # seconds
__version__ = "1.1.0"

# 工具函数区
def _names(list_or_none: Optional[List[Any]]) -> List[str]:
    lst = list_or_none or []
    out = []
    for x in lst:
        if isinstance(x, dict):
            n = x.get("name")
            if n is not None:
                out.append(str(n))
        else:
            out.append(str(x))
    return out

def _wrap_names(names: Iterable[str]) -> List[Dict[str, str]]:
    return [{"name": str(n)} for n in names]

def _load_json_arg(s: str):
    """支持 @file.json；容忍 Windows CMD 单引号 JSON。"""
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

def _cidr_to_subnet_str(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    return f"{net.network_address} {net.netmask}"

def _suggest_similar(target: str, pool: list, limit: int = 8) -> list:
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

def _to_enable_disable(val: Any) -> str:
    """将 True/False/'true'/'false' 等统一为 'enable'/'disable'；传入 'enable'/'disable' 原样返回。"""
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("enable", "disable"):
            return v
        if v in ("true", "yes", "1"):
            return "enable"
        if v in ("false", "no", "0"):
            return "disable"
    return "enable" if bool(val) else "disable"

def _normalize_vip_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """兼容 7.2/7.4：把 mappedip 规范成 [{'range': 'ip-or-range'}]；extip 去掉 /32 等 CIDR；portforward 统一成 enable/disable。"""
    p = dict(payload or {})
    # extip: 剥离 CIDR（如 x.x.x.x/32 -> x.x.x.x）
    extip = p.get("extip")
    if isinstance(extip, str) and "/" in extip:
        try:
            net = ipaddress.ip_network(extip, strict=False)
            p["extip"] = str(net.network_address)
        except Exception:
            pass
    # mappedip: 统一成 [{'range': '...'}] 列表
    mi = p.get("mappedip")
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
    if mi is not None:
        p["mappedip"] = _to_range_list(mi)
    # portforward: 统一为 enable/disable
    if "portforward" in p:
        p["portforward"] = _to_enable_disable(p["portforward"])
    # 端口转字符串（两边版本都能接受）
    if "extport" in p and p["extport"] is not None:
        p["extport"] = str(p["extport"])
    if "mappedport" in p and p["mappedport"] is not None:
        p["mappedport"] = str(p["mappedport"])
    # 显式类型
    p.setdefault("type", "static-nat")
    return p

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
        r = self.session.request(method=method.upper(), url=url, params=self._params(params), json=json_body,
                                 timeout=DEFAULT_TIMEOUT, verify=self.verify_ssl)
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

    # def get_policy_by_id(self, policy_id: int) -> Optional[Dict[str, Any]]:
    #     try:
    #         data = self._req("GET", f"/api/v2/cmdb/firewall/policy/{policy_id}")
    #         if isinstance(data, dict) and "results" in data:
    #             return data["results"]
    #         return data if isinstance(data, dict) else None
    #     except RuntimeError as e:
    #         if " 424 " in str(e) or 'http_status":424' in str(e):
    #             for p in self.list_policies():
    #                 try:
    #                     if int(p.get("policyid") or -1) == int(policy_id):
    #                         return p
    #                 except Exception:
    #                     continue
    #         raise

    def get_policy_by_id(self, policy_id: int) -> Optional[Dict[str, Any]]:
        """Robust: handle dict/list/results shapes and fallback to list scan."""
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
            # 无论什么错误（不仅仅是 424），都回退到 list
            return _from_list(self.list_policies())

        # 常见形态 1：直接就是一个策略 dict
        if isinstance(data, dict):
            if "policyid" in data:
                return data
            # 常见形态 2：{"status":"success","results":{...}} 或 {"results":[{...}]}
            if "results" in data:
                res = data["results"]
                if isinstance(res, dict) and "policyid" in res:
                    return res
                if isinstance(res, list) and res:
                    got = _from_list(res)
                    if got:
                        return got
                # results 为空则回退
                return _from_list(self.list_policies())
            # 其他 dict 形态不识别 -> 回退
            return _from_list(self.list_policies())

        # 常见形态 3：居然直接给了一个 list
        if isinstance(data, list):
            got = _from_list(data)
            if got:
                return got
            return _from_list(self.list_policies())

        # 兜底
        return _from_list(self.list_policies())

    def get_policy_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for p in self.list_policies():
            if str(p.get("name") or "").strip() == str(name).strip():
                return p
        return None

    def create_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._req("POST", "/api/v2/cmdb/firewall/policy", json_body=payload)
        # 尝试按名称返回
        if "name" in payload:
            got = self.get_policy_by_name(payload["name"])
            if got: return got
        # 兜底：返回请求体
        return payload

    def update_policy(self, policy_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=payload)
        return self.get_policy_by_id(policy_id) or {"policyid": policy_id, **payload}

    # def update_policy_addrs(self, policy_id: int, *, add_src: List[str] = None, add_dst: List[str] = None,
    #                         remove_src: List[str] = None, remove_dst: List[str] = None) -> Dict[str, Any]:
    #     add_src = add_src or []
    #     add_dst = add_dst or []
    #     remove_src = remove_src or []
    #     remove_dst = remove_dst or []

    #     p = self.get_policy_by_id(policy_id)
    #     if not p:
    #         raise RuntimeError(f"Policy {policy_id} not found")

    #     srcaddr = set(_names(p.get("srcaddr")))
    #     dstaddr = set(_names(p.get("dstaddr")))

    #     srcaddr |= set(add_src)
    #     dstaddr |= set(add_dst)
    #     srcaddr -= set(remove_src)
    #     dstaddr -= set(remove_dst)

    #     body = {"srcaddr": _wrap_names(sorted(srcaddr)),
    #             "dstaddr": _wrap_names(sorted(dstaddr))}
    #     self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=body)
    #     return self.get_policy_by_id(policy_id)

    # def update_policy_addrs(self, policy_id: int, *, add_src: List[str] = None, add_dst: List[str] = None,
    #                         remove_src: List[str] = None, remove_dst: List[str] = None) -> Dict[str, Any]:
    #     add_src = add_src or []
    #     add_dst = add_dst or []
    #     remove_src = remove_src or []
    #     remove_dst = remove_dst or []

    #     p = self.get_policy_by_id(policy_id)
    #     if not p:
    #         raise RuntimeError(f"Policy {policy_id} not found")

    #     # 当前值集合化
    #     cur_src = set((x.get("name") if isinstance(x, dict) else x) for x in (p.get("srcaddr") or []))
    #     cur_dst = set((x.get("name") if isinstance(x, dict) else x) for x in (p.get("dstaddr") or []))

    #     new_src = sorted((cur_src | set(add_src)) - set(remove_src))
    #     new_dst = sorted((cur_dst | set(add_dst)) - set(remove_dst))

    #     # 先尝试“只改 addr 列表”的轻量 PUT
    #     body_light = {
    #         "srcaddr": [{"name": n} for n in new_src],
    #         "dstaddr": [{"name": n} for n in new_dst],
    #     }
    #     try:
    #         self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=body_light)
    #         return self.get_policy_by_id(policy_id)
    #     except RuntimeError as e:
    #         msg = str(e)
    #         # 某些版本会对轻量 PUT 返回 500 -7 或 424；回退为“整条策略合并更新”
    #         if ('"http_status":500' in msg and ('"error":-7' in msg or '"error": -7' in msg)) or ' 424 ' in msg:
    #             pass
    #         else:
    #             raise

    #     # 构造完整体（避免携带只读/无效字段）
    #     keep_keys = {
    #         "name", "status", "action", "srcintf", "dstintf", "service",
    #         "schedule", "nat", "logtraffic",
    #         "ips-sensor", "av-profile", "webfilter-profile", "application-list", "ssl-ssh-profile",
    #         "comments", "comment"  # 有的版本用 comments，有的用 comment
    #     }
    #     body_full = {}
    #     for k, v in (p or {}).items():
    #         if k in keep_keys and v is not None:
    #             body_full[k] = v

    #     # 强制覆盖 addr 列表为新值
    #     body_full["srcaddr"] = [{"name": n} for n in new_src]
    #     body_full["dstaddr"] = [{"name": n} for n in new_dst]

    #     # 再试一次：整条策略 PUT
    #     self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=body_full)
    #     return self.get_policy_by_id(policy_id)
    def update_policy_addrs(self, policy_id: int, *, add_src: List[str] = None, add_dst: List[str] = None,
                            remove_src: List[str] = None, remove_dst: List[str] = None) -> Dict[str, Any]:
        add_src = add_src or []
        add_dst = add_dst or []
        remove_src = remove_src or []
        remove_dst = remove_dst or []

        p = self.get_policy_by_id(policy_id)
        if not p:
            raise RuntimeError(f"Policy {policy_id} not found")

        # 现有 -> 名称集合
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

        # 关键规则：如果包含 all 且成员数 > 1，则移除 all，避免 500 -7
        if "all" in new_src and len(new_src) > 1:
            new_src = [n for n in new_src if n != "all"]
        if "all" in new_dst and len(new_dst) > 1:
            new_dst = [n for n in new_dst if n != "all"]

        body_light = {
            "srcaddr": [{"name": n} for n in new_src],
            "dstaddr": [{"name": n} for n in new_dst],
        }
        try:
            self._req("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json_body=body_light)
            return self.get_policy_by_id(policy_id)
        except RuntimeError as e:
            msg = str(e)
            # 轻量 PUT 失败（如 500 -7/424）→ 回退整条合并
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
        body_full = {}
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
        # 尝试两种 subnet 形态
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
        self._req("PUT", f"/api/v2/cmdb/firewall/address/{url_quote(name, safe='')}", json_body=payload)
        return self.get_address(name) or {"name": name, **payload}

    def delete_address(self, name: str) -> None:
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
            body["member"] = _wrap_names(members)
        body.update(extra or {})
        self._req("POST", "/api/v2/cmdb/firewall/addrgrp", json_body=body)
        return self.get_addrgrp(name) or body

    def update_addrgrp(self, name: str, *, new_name: Optional[str] = None, members: Optional[List[str]] = None, comment: Optional[str] = None, **extra) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if new_name:
            body["name"] = new_name
        if comment is not None:
            body["comment"] = comment
        if members is not None:
            body["member"] = _wrap_names(members)
        if extra:
            body.update(extra)
        self._req("PUT", f"/api/v2/cmdb/firewall/addrgrp/{url_quote(name, safe='')}", json_body=body)
        return self.get_addrgrp(new_name or name) or {"name": new_name or name, **body}

    def delete_addrgrp(self, name: str) -> None:
        self._req("DELETE", f"/api/v2/cmdb/firewall/addrgrp/{url_quote(name, safe='')}")

    def add_members_to_addrgrp(self, name: str, to_add: List[str]) -> Dict[str, Any]:
        grp = self.get_addrgrp(name)
        if not grp:
            raise RuntimeError(f"Address-Group '{name}' not found")
        current = set(_names(grp.get("member")))
        merged = sorted(current.union(set(to_add)))
        return self.update_addrgrp(name, members=merged)

    def remove_members_from_addrgrp(self, name: str, to_remove: List[str]) -> Dict[str, Any]:
        grp = self.get_addrgrp(name)
        if not grp:
            raise RuntimeError(f"Address-Group '{name}' not found")
        current = set(_names(grp.get("member")))
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
        # -------- VIP (Virtual IP)
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
        """创建 VIP；优先用 7.2/7.4 通吃的标准形态：mappedip=[{'range': '...'}]；失败再做形态互转重试。"""
        # 先做标准化
        p0 = _normalize_vip_payload(payload)
        try:
            self._req("POST", "/api/v2/cmdb/firewall/vip", json_body=p0)
            return self.get_vip(p0.get("name")) or p0
        except RuntimeError as e:
            msg = str(e)

        # 形态重试：部分 7.4 也接受 'mappedip': 'x.x.x.x' 或 ['x.x.x.x']
        alt_shapes = []
        mi = payload.get("mappedip")
        if isinstance(mi, list):
            # 尝试 list[str]
            alt_shapes.append(list(mi))
            # 再尝试 单字符串（若只有一个元素）
            if len(mi) == 1:
                alt_shapes.append(mi[0])
        elif isinstance(mi, str):
            # 尝试 list[str]
            alt_shapes.append([mi])

        for shape in alt_shapes:
            p2 = dict(payload)
            # 也把 extip 正常化一次，避免 /32
            p2 = _normalize_vip_payload(p2)
            p2["mappedip"] = shape
            try:
                self._req("POST", "/api/v2/cmdb/firewall/vip", json_body=p2)
                return self.get_vip(p2.get("name")) or p2
            except RuntimeError:
                continue

        # 最后还是失败，抛原始错误
        raise

    def update_vip(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """更新 VIP；与 create_vip 同样的形态兼容处理。"""
        p0 = _normalize_vip_payload(payload)
        try:
            self._req("PUT", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}", json_body=p0)
            return self.get_vip(name) or p0
        except RuntimeError:
            pass

        # 形态重试
        alt_shapes = []
        mi = payload.get("mappedip")
        if isinstance(mi, list):
            alt_shapes.append(list(mi))
            if len(mi) == 1:
                alt_shapes.append(mi[0])
        elif isinstance(mi, str):
            alt_shapes.append([mi])

        for shape in alt_shapes:
            p2 = dict(payload)
            p2 = _normalize_vip_payload(p2)
            p2["mappedip"] = shape
            try:
                self._req("PUT", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}", json_body=p2)
                return self.get_vip(name) or p2
            except RuntimeError:
                continue

        raise


    def delete_vip(self, name: str) -> None:
        self._req("DELETE", f"/api/v2/cmdb/firewall/vip/{url_quote(name, safe='')}")

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
        "srcintf": _names(p.get("srcintf")),
        "dstintf": _names(p.get("dstintf")),
        "srcaddr": _names(p.get("srcaddr")),
        "dstaddr": _names(p.get("dstaddr")),
        "service": _names(p.get("service")),
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

def print_json(obj: Any):
    print(json.dumps(obj, ensure_ascii=False, indent=2))

# ---------- Smart grouping / attach ----------
def _match_base_groups(all_groups: List[Dict[str, Any]], base: str) -> List[Tuple[str, int]]:
    exact = []
    pat = re.compile(rf"^{re.escape(base)}(?:-(\d+))?$")
    for g in all_groups:
        name = g.get("name") or ""
        m = pat.match(name)
        if m:
            idx = int(m.group(1)) if m.group(1) else 1
            exact.append((name, idx))
    exact.sort(key=lambda x: x[1])
    return exact

def smart_fill_addrgrps(client: FortiGateClient, base_name: str, new_members: List[str], chunk_size: int = 255, comment: Optional[str] = None) -> Dict[str, Any]:
    groups = client.list_addrgrps()
    base_groups = _match_base_groups(groups, base_name)

    present: List[str] = []
    group_info: Dict[str, List[str]] = {}
    for gname, _ in base_groups:
        g = client.get_addrgrp(gname)
        mems = _names(g.get("member")) if g else []
        group_info[gname] = mems
        present.extend(mems)
    present_set = set(present)
    to_add = [m for m in new_members if m not in present_set]

    if not base_groups:
        client.create_addrgrp(base_name, members=[], comment=comment)
        base_groups = [(base_name, 1)]
        group_info[base_name] = []

    created_groups = []
    updated_groups = []

    for gname, _ in base_groups:
        capacity = chunk_size - len(group_info[gname])
        if capacity <= 0 or not to_add:
            continue
        take = to_add[:capacity]
        if take:
            out = client.add_members_to_addrgrp(gname, take)
            updated_groups.append({"name": gname, "added": take, "new_count": len(_names(out.get("member")))})
            to_add = to_add[capacity:]

    next_idx = max([idx for _, idx in base_groups]) + 1 if base_groups else 1
    while to_add:
        batch = to_add[:chunk_size]
        gname = base_name if next_idx == 1 else f"{base_name}-{next_idx}"
        if next_idx != 1:
            client.create_addrgrp(gname, members=[], comment=comment)
        out = client.add_members_to_addrgrp(gname, batch) if batch else client.get_addrgrp(gname)
        created_groups.append({"name": gname, "added": batch, "new_count": len(_names(out.get("member")))})
        to_add = to_add[chunk_size:]
        next_idx += 1

    return {
        "base": base_name,
        "chunk_size": chunk_size,
        "created_groups": created_groups,
        "updated_groups": updated_groups,
        "skipped_existing": len(new_members) - (sum(len(x["added"]) for x in created_groups)+sum(len(x["added"]) for x in updated_groups)),
    }

def attach_groups_to_policy(client: FortiGateClient, policy_id: int, base_name: str, direction: str = "dst") -> Dict[str, Any]:
    direction = direction.lower()
    if direction not in ("src", "dst"):
        raise RuntimeError("direction must be 'src' or 'dst'")
    groups = client.list_addrgrps()
    base_groups = _match_base_groups(groups, base_name)
    names = [g for g, _ in base_groups]
    if not names:
        raise RuntimeError(f"No groups found for base '{base_name}'")
    if direction == "src":
        out = client.update_policy_addrs(policy_id, add_src=names)
    else:
        out = client.update_policy_addrs(policy_id, add_dst=names)
    return {"policy": pick_policy_fields(out), "attached_groups": names, "direction": direction}

def vip_brief(v: Dict[str, Any]) -> Dict[str, Any]:
    """输出 VIP 简要信息"""
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

def main():
    ap = argparse.ArgumentParser(description="FortiGate Policy & Address Toolkit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--host", required=True, help="e.g. https://10.0.0.1:10443")
    ap.add_argument("--token", required=True, help="API token")
    ap.add_argument("--vdom", default=None, help="VDOM name (e.g. SL-Internet)")
    ap.add_argument("--insecure", action="store_true", help="Disable SSL verification")

    sub = ap.add_subparsers(dest="cmd")

    # ---- Policy inspect/search ----
    s1 = sub.add_parser("policy-id", help="Inspect policy by ID"); s1.add_argument("--policy-id", type=int, required=True)
    s2 = sub.add_parser("policy-name", help="Inspect policy by Name"); s2.add_argument("--policy-name", required=True)
    s3 = sub.add_parser("find-policies-with", help="Find policies referencing an object"); s3.add_argument("--object-name", required=True)
    sp = sub.add_parser("search-policies", help="Search policies by name substring"); sp.add_argument("--q", required=True)

    # ---- Policy create/update ----
    cp = sub.add_parser("create-policy", help="Create policy (JSON or @file.json)")
    cp.add_argument("--data", required=True, help="JSON or @file, payload for /firewall/policy")

    cps = sub.add_parser("create-policy-simple", help="Create policy without JSON")
    cps.add_argument("--name", required=True)
    cps.add_argument("--srcintf", required=True, help="Comma-separated interface names")
    cps.add_argument("--dstintf", required=True, help="Comma-separated interface names")
    cps.add_argument("--srcaddr", required=True, help="Comma-separated address/addrgrp names")
    cps.add_argument("--dstaddr", required=True, help="Comma-separated address/addrgrp names")
    cps.add_argument("--service", default="ALL", help="Comma-separated services (default ALL)")
    cps.add_argument("--action", choices=["accept","deny"], default="accept")
    cps.add_argument("--schedule", default="always")
    cps.add_argument("--nat", action="store_true")
    cps.add_argument("--status", choices=["enable","disable"], default="enable")
    cps.add_argument("--logtraffic", choices=["utm","all","disable"], default=None)
    cps.add_argument("--comment", default=None)

    up = sub.add_parser("update-policy", help="Update policy by ID (JSON or @file.json)")
    up.add_argument("--policy-id", type=int, required=True)
    up.add_argument("--data", required=True, help="JSON or @file")

    upf = sub.add_parser("update-policy-fields", help="Update common policy fields without JSON")
    upf.add_argument("--policy-id", type=int, required=True)
    upf.add_argument("--name", default=None)
    upf.add_argument("--srcintf", default=None)
    upf.add_argument("--dstintf", default=None)
    upf.add_argument("--srcaddr", default=None)
    upf.add_argument("--dstaddr", default=None)
    upf.add_argument("--service", default=None)
    upf.add_argument("--action", choices=["accept","deny"], default=None)
    upf.add_argument("--schedule", default=None)
    upf.add_argument("--nat", type=str, choices=["true","false"], default=None)
    upf.add_argument("--status", choices=["enable","disable"], default=None)
    upf.add_argument("--logtraffic", choices=["utm","all","disable"], default=None)
    upf.add_argument("--comment", default=None)

    # ---- Address CRUD/search ----
    sub.add_parser("list-addresses", help="List addresses")
    sa = sub.add_parser("search-addresses", help="Search addresses by substring"); sa.add_argument("--q", required=True)
    ga = sub.add_parser("get-address", help="Get address by name"); ga.add_argument("--name", required=True)

    ca = sub.add_parser("create-address", help="Create address (JSON or @file.json)")
    ca.add_argument("--data", required=True, help='JSON or @file')

    cai = sub.add_parser("create-address-ipmask", help="Create ipmask address without JSON")
    cai.add_argument("--name", required=True); cai.add_argument("--cidr", required=True); cai.add_argument("--comment", default=None)

    ua = sub.add_parser("update-address", help="Update address by name (JSON or @file.json)")
    ua.add_argument("--name", required=True); ua.add_argument("--data", required=True)

    uac = sub.add_parser("update-address-comment", help="Update address comment (no JSON)")
    uac.add_argument("--name", required=True); uac.add_argument("--comment", required=True)

    da = sub.add_parser("delete-address", help="Delete address by name"); da.add_argument("--name", required=True)

    # ---- Address-Group CRUD/search ----
    sub.add_parser("list-addrgrps", help="List address-groups")
    sg = sub.add_parser("search-addrgrps", help="Search addrgrps by substring"); sg.add_argument("--q", required=True)
    gg = sub.add_parser("get-addrgrp", help="Get addrgrp by name"); gg.add_argument("--name", required=True)

    cg = sub.add_parser("create-addrgrp", help="Create addrgrp")
    cg.add_argument("--name", required=True); cg.add_argument("--members", default="", help="Comma-separated members")
    cg.add_argument("--comment", default=None); cg.add_argument("--skip-validate-members", action="store_true")

    ug = sub.add_parser("update-addrgrp", help="Replace addrgrp fields/members")
    ug.add_argument("--name", required=True); ug.add_argument("--new-name", default=None)
    ug.add_argument("--members", default=None, help="Comma-separated members (replaces all)")
    ug.add_argument("--comment", default=None); ug.add_argument("--skip-validate-members", action="store_true")

    ag = sub.add_parser("add-to-addrgrp", help="Add members to addrgrp (idempotent)")
    ag.add_argument("--name", required=True); ag.add_argument("--members", required=True)
    ag.add_argument("--skip-validate-members", action="store_true")

    rg = sub.add_parser("remove-from-addrgrp", help="Remove members from addrgrp")
    rg.add_argument("--name", required=True); rg.add_argument("--members", required=True)

    dg = sub.add_parser("delete-addrgrp", help="Delete addrgrp by name"); dg.add_argument("--name", required=True)

    fgm = sub.add_parser("find-groups-with-member", help="Find addrgrps containing a given object")
    fgm.add_argument("--name", required=True)

    # ---- Policy mutate src/dst addrs ----
    pm = sub.add_parser("policy-set-addrs", help="Mutate policy srcaddr/dstaddr (add/remove names)")
    pm.add_argument("--policy-id", type=int, required=True)
    pm.add_argument("--add-src", default="", help="Comma-separated names")
    pm.add_argument("--add-dst", default="", help="Comma-separated names")
    pm.add_argument("--remove-src", default="", help="Comma-separated names")
    pm.add_argument("--remove-dst", default="", help="Comma-separated names")

        # ---- VIP CRUD/search ----
    sub.add_parser("list-vips", help="List virtual IPs (firewall/vip)")
    sv = sub.add_parser("search-vips", help="Search VIPs by name substring"); sv.add_argument("--q", required=True)
    gv = sub.add_parser("get-vip", help="Get VIP by name"); gv.add_argument("--name", required=True)

    cv = sub.add_parser("create-vip", help="Create VIP (JSON or @file.json)")
    cv.add_argument("--data", required=True, help="JSON or @file")

    cvs = sub.add_parser("create-vip-simple", help="Create 1:1 static NAT VIP (no JSON)")
    cvs.add_argument("--name", required=True)
    cvs.add_argument("--extip", required=True, help="External IP or range")
    cvs.add_argument("--mappedip", required=True, help="Mapped IP (internal)")
    cvs.add_argument("--extintf", default=None, help="External interface name, e.g. 'any' or 'port1'")
    cvs.add_argument("--comment", default=None)

    cvp = sub.add_parser("create-vip-portforward", help="Create port-forward VIP (no JSON)")
    cvp.add_argument("--name", required=True)
    cvp.add_argument("--extip", required=True)
    cvp.add_argument("--mappedip", required=True)
    cvp.add_argument("--protocol", choices=["tcp", "udp", "sctp"], required=True)
    cvp.add_argument("--extport", required=True)
    cvp.add_argument("--mappedport", required=True)
    cvp.add_argument("--extintf", default=None)
    cvp.add_argument("--comment", default=None)

    uv = sub.add_parser("update-vip", help="Update VIP by name (JSON or @file.json)")
    uv.add_argument("--name", required=True); uv.add_argument("--data", required=True)

    uvf = sub.add_parser("update-vip-fields", help="Update VIP fields (no JSON)")
    uvf.add_argument("--name", required=True)
    uvf.add_argument("--extip", default=None)
    uvf.add_argument("--mappedip", default=None)
    uvf.add_argument("--extintf", default=None)
    uvf.add_argument("--portforward", default=None, help="enable/disable/true/false")
    uvf.add_argument("--protocol", default=None, choices=["tcp","udp","sctp"])
    uvf.add_argument("--extport", default=None)
    uvf.add_argument("--mappedport", default=None)
    uvf.add_argument("--comment", default=None)

    dv = sub.add_parser("delete-vip", help="Delete VIP by name"); dv.add_argument("--name", required=True)


    # ---- Smart & attach ----
    sc = sub.add_parser("smart-fill-addrgrps", help="Spread members across groups with <= chunk-size; auto-create -2/-3...")
    sc.add_argument("--base-name", required=True); sc.add_argument("--members", default="")
    sc.add_argument("--members-file", default=None); sc.add_argument("--chunk-size", type=int, default=255)
    sc.add_argument("--comment", default=None)

    at = sub.add_parser("attach-grps-to-policy", help="Attach base-name groups to a policy (src or dst)")
    at.add_argument("--policy-id", type=int, required=True); at.add_argument("--base-name", required=True)
    at.add_argument("--direction", choices=["src", "dst"], default="dst")

    # ---- Probe ----
    pr = sub.add_parser("probe", help="Connectivity probe for monitor+cmdb endpoints")

    args = ap.parse_args()
    client = FortiGateClient(args.host, args.token, args.vdom, verify_ssl=not args.insecure)

    try:
        # ===== Policies (inspect/search) =====
        if args.cmd == "policy-id":
            p = client.get_policy_by_id(args.policy_id)
            if not p: print_json({"error": f"Policy {args.policy_id} not found"}); sys.exit(1)
            print_json({"policy": pick_policy_fields(p)})

        elif args.cmd == "policy-name":
            p = client.get_policy_by_name(args.policy_name)
            if not p: print_json({"error": f"Policy '{args.policy_name}' not found"}); sys.exit(1)
            print_json({"policy": pick_policy_fields(p)})

        elif args.cmd == "find-policies-with":
            res = []
            for p in client.list_policies():
                if args.object_name in _names(p.get("srcaddr")) or args.object_name in _names(p.get("dstaddr")):
                    res.append(pick_policy_fields(p))
            print_json({"referencing_policies": res, "count": len(res)})

        elif args.cmd == "search-policies":
            q = args.q
            res = []
            for p in client.list_policies():
                if q.lower() in str(p.get("name") or "").lower():
                    res.append(pick_policy_fields(p))
            print_json({"query": q, "matches": res, "count": len(res)})

        # ===== Policies (create/update) =====
        elif args.cmd == "create-policy":
            payload = _load_json_arg(args.data)
            out = client.create_policy(payload)
            print_json({"created": pick_policy_fields(out) if isinstance(out, dict) else out})

        elif args.cmd == "create-policy-simple":
            payload = {
                "name": args.name,
                "srcintf": _wrap_names([x.strip() for x in args.srcintf.split(",") if x.strip()]),
                "dstintf": _wrap_names([x.strip() for x in args.dstintf.split(",") if x.strip()]),
                "srcaddr": _wrap_names([x.strip() for x in args.srcaddr.split(",") if x.strip()]),
                "dstaddr": _wrap_names([x.strip() for x in args.dstaddr.split(",") if x.strip()]),
                "service": _wrap_names([x.strip() for x in args.service.split(",") if x.strip()]),
                "action": args.action,
                "schedule": args.schedule,
                "status": args.status,
            }
            if args.logtraffic: payload["logtraffic"] = args.logtraffic
            if args.comment: payload["comments"] = args.comment
            if args.nat: payload["nat"] = True
            out = client.create_policy(payload)
            print_json({"created": pick_policy_fields(out) if isinstance(out, dict) else out})

        elif args.cmd == "update-policy":
            payload = _load_json_arg(args.data)
            out = client.update_policy(args.policy_id, payload)
            print_json({"updated": pick_policy_fields(out) if isinstance(out, dict) else out})

        elif args.cmd == "update-policy-fields":
            body: Dict[str, Any] = {}
            if args.name is not None: body["name"] = args.name
            if args.srcintf is not None: body["srcintf"] = _wrap_names([x.strip() for x in args.srcintf.split(",") if x.strip()])
            if args.dstintf is not None: body["dstintf"] = _wrap_names([x.strip() for x in args.dstintf.split(",") if x.strip()])
            if args.srcaddr is not None: body["srcaddr"] = _wrap_names([x.strip() for x in args.srcaddr.split(",") if x.strip()])
            if args.dstaddr is not None: body["dstaddr"] = _wrap_names([x.strip() for x in args.dstaddr.split(",") if x.strip()])
            if args.service is not None: body["service"] = _wrap_names([x.strip() for x in args.service.split(",") if x.strip()])
            if args.action is not None: body["action"] = args.action
            if args.schedule is not None: body["schedule"] = args.schedule
            if args.status is not None: body["status"] = args.status
            if args.nat is not None: body["nat"] = (args.nat == "true")
            if args.logtraffic is not None: body["logtraffic"] = args.logtraffic
            if args.comment is not None: body["comments"] = args.comment
            out = client.update_policy(args.policy_id, body)
            print_json({"updated": pick_policy_fields(out) if isinstance(out, dict) else out})

        # ===== Addresses =====
        elif args.cmd == "list-addresses":
            print_json({"addresses": [address_brief(a) for a in client.list_addresses()]})

        elif args.cmd == "search-addresses":
            q = args.q
            names = [a.get("name") for a in client.list_addresses() if a.get("name")]
            matchs = [n for n in names if q.lower() in n.lower()] or _suggest_similar(q, names)
            print_json({"query": q, "matches": matchs, "count": len(matchs)})

        elif args.cmd == "get-address":
            a = client.get_address(args.name)
            if not a:
                names = [x.get("name") for x in client.list_addresses() if x.get("name")]
                print_json({"error": f"Address '{args.name}' not found", "suggestions": _suggest_similar(args.name, names)})
                sys.exit(1)
            print_json({"address": a, "brief": address_brief(a)})

        elif args.cmd == "create-address":
            payload = _load_json_arg(args.data)
            out = client.create_address(payload)
            print_json({"created": out, "brief": address_brief(out)})

        elif args.cmd == "create-address-ipmask":
            
            # # 优先用数组形态的 subnet；失败会在 create_address 里自动换形态重试
            # subnet = _cidr_to_subnet_str(args.cidr)
            # ip_part, mask_part = subnet.split(" ", 1)
            # payload = {"name": args.name, "type": "ipmask", "subnet": [ip_part, mask_part]}
            # if args.comment is not None:
            #     payload["comment"] = args.comment
            # out = client.create_address(payload)
            # print_json({"created": out, "brief": address_brief(out)})

            # 上面代码报错，以下代码正常
            subnet = _cidr_to_subnet_str(args.cidr)
            payload = {"name": args.name, "type": "ipmask", "subnet": subnet}
            if args.comment is not None:
                payload["comment"] = args.comment
            out = client.create_address(payload)
            print_json({"created": out, "brief": address_brief(out)})

        elif args.cmd == "update-address":
            payload = _load_json_arg(args.data)
            out = client.update_address(args.name, payload)
            print_json({"updated": out, "brief": address_brief(out)})

        elif args.cmd == "update-address-comment":
            out = client.update_address(args.name, {"comment": args.comment})
            print_json({"updated": out, "brief": address_brief(out)})

        elif args.cmd == "delete-address":
            client.delete_address(args.name)
            print_json({"deleted": args.name})

        # ===== Address-Groups =====
        elif args.cmd == "list-addrgrps":
            groups = client.list_addrgrps()
            out = []
            for g in groups:
                mems = _names(g.get("member"))
                out.append({"name": g.get("name"), "members": mems, "count": len(mems), "comment": g.get("comment")})
            print_json({"addrgrps": out})

        elif args.cmd == "search-addrgrps":
            q = args.q
            groups = client.list_addrgrps()
            names = [g.get("name") for g in groups if g.get("name")]
            matchs = [n for n in names if q.lower() in n.lower()] or _suggest_similar(q, names)
            print_json({"query": q, "matches": matchs, "count": len(matchs)})

        elif args.cmd == "get-addrgrp":
            g = client.get_addrgrp(args.name)
            if not g:
                groups = client.list_addrgrps()
                names = [x.get("name") for x in groups if x.get("name")]
                print_json({"error": f"Addrgrp '{args.name}' not found", "suggestions": _suggest_similar(args.name, names)})
                sys.exit(1)
            print_json({"addrgrp": {"name": g.get("name"), "members": _names(g.get("member")), "count": len(_names(g.get("member"))), "comment": g.get("comment"), "uuid": g.get("uuid")}})

        elif args.cmd == "create-addrgrp":
            members = [x.strip() for x in (args.members or "").split(",") if x.strip()]
            if members and not args.skip_validate_members:
                not_found = [m for m in members if not client.object_exists(m)]
                if not_found:
                    print_json({"error": "Some members do not exist (address/addrgrp)", "not_found": not_found}); sys.exit(1)
            out = client.create_addrgrp(args.name, members=members, comment=args.comment)
            print_json({"created": out})

        elif args.cmd == "update-addrgrp":
            members = None if args.members is None else [x.strip() for x in args.members.split(",") if x.strip()]
            if members is not None and members and not args.skip_validate_members:
                not_found = [m for m in members if not client.object_exists(m)]
                if not_found:
                    print_json({"error": "Some members do not exist (address/addrgrp)", "not_found": not_found}); sys.exit(1)
            out = client.update_addrgrp(args.name, new_name=args.new_name, members=members, comment=args.comment)
            print_json({"updated": out})

        elif args.cmd == "add-to-addrgrp":
            members = [x.strip() for x in args.members.split(",") if x.strip()]
            if members and not args.skip_validate_members:
                not_found = [m for m in members if not client.object_exists(m)]
                if not_found:
                    print_json({"error": "Some members do not exist (address/addrgrp)", "not_found": not_found}); sys.exit(1)
            out = client.add_members_to_addrgrp(args.name, members)
            print_json({"updated": out, "count": len(_names(out.get("member")))})

        elif args.cmd == "remove-from-addrgrp":
            members = [x.strip() for x in args.members.split(",") if x.strip()]
            out = client.remove_members_from_addrgrp(args.name, members)
            print_json({"updated": out, "count": len(_names(out.get("member")))})

        elif args.cmd == "delete-addrgrp":
            client.delete_addrgrp(args.name)
            print_json({"deleted": args.name})

        elif args.cmd == "find-groups-with-member":
            n = args.name
            grps = []
            for g in client.list_addrgrps():
                mems = _names(g.get("member"))
                if n in mems:
                    grps.append({"name": g.get("name"), "count": len(mems)})
            print_json({"name": n, "groups": grps, "count": len(grps)})

                # ===== VIPs =====
        elif args.cmd == "list-vips":
            vips = client.list_vips()
            print_json({"vips": [vip_brief(v) for v in vips], "count": len(vips)})

        elif args.cmd == "search-vips":
            q = args.q
            names = [v.get("name") for v in client.list_vips() if v.get("name")]
            matchs = [n for n in names if q.lower() in n.lower()] or _suggest_similar(q, names)
            print_json({"query": q, "matches": matchs, "count": len(matchs)})

        elif args.cmd == "get-vip":
            v = client.get_vip(args.name)
            if not v:
                names = [x.get("name") for x in client.list_vips() if x.get("name")]
                print_json({"error": f"VIP '{args.name}' not found", "suggestions": _suggest_similar(args.name, names)})
                sys.exit(1)
            print_json({"vip": v, "brief": vip_brief(v)})

        elif args.cmd == "create-vip":
            payload = _load_json_arg(args.data)
            out = client.create_vip(payload)
            print_json({"created": out, "brief": vip_brief(out)})

        elif args.cmd == "create-vip-simple":
            body = {
                "name": args.name,
                "extip": args.extip,
                "mappedip": args.mappedip,   # 若报 500 -5 会在 create_vip 中自动在 str/list 之间重试
                "type": "static-nat",        # 显式声明
            }
            if args.extintf: body["extintf"] = args.extintf
            if args.comment: body["comment"] = args.comment
            out = client.create_vip(body)
            print_json({"created": out, "brief": vip_brief(out)})

        elif args.cmd == "create-vip-portforward":
            body = {
                "name": args.name,
                "extip": args.extip,
                "mappedip": args.mappedip,
                "portforward": "enable",
                "protocol": args.protocol,
                "extport": str(args.extport),
                "mappedport": str(args.mappedport),
                "type": "static-nat",
            }
            if args.extintf: body["extintf"] = args.extintf
            if args.comment: body["comment"] = args.comment
            out = client.create_vip(body)
            print_json({"created": out, "brief": vip_brief(out)})

        elif args.cmd == "update-vip":
            payload = _load_json_arg(args.data)
            out = client.update_vip(args.name, payload)
            print_json({"updated": out, "brief": vip_brief(out)})

        elif args.cmd == "update-vip-fields":
            body = {}
            if args.extip is not None: body["extip"] = args.extip
            if args.mappedip is not None: body["mappedip"] = args.mappedip
            if args.extintf is not None: body["extintf"] = args.extintf
            if args.portforward is not None: body["portforward"] = _to_enable_disable(args.portforward)
            if args.protocol is not None: body["protocol"] = args.protocol
            if args.extport is not None: body["extport"] = str(args.extport)
            if args.mappedport is not None: body["mappedport"] = str(args.mappedport)
            if args.comment is not None: body["comment"] = args.comment
            out = client.update_vip(args.name, body)
            print_json({"updated": out, "brief": vip_brief(out)})

        elif args.cmd == "delete-vip":
            client.delete_vip(args.name)
            print_json({"deleted": args.name})


        # ===== Policy mutate src/dst addr lists =====
        elif args.cmd == "policy-set-addrs":
            out = client.update_policy_addrs(
                args.policy_id,
                add_src=[x for x in args.add_src.split(",") if x],
                add_dst=[x for x in args.add_dst.split(",") if x],
                remove_src=[x for x in args.remove_src.split(",") if x],
                remove_dst=[x for x in args.remove_dst.split(",") if x],
            )
            print_json({"policy": pick_policy_fields(out)})

        # ===== Smart & attach =====
        elif args.cmd == "smart-fill-addrgrps":
            members = [x.strip() for x in (args.members or "").split(",") if x.strip()]
            if args.members_file:
                with open(args.members_file, "r", encoding="utf-8") as f:
                    for line in f:
                        s = line.strip()
                        if s:
                            members.append(s)
            if not members:
                print_json({"error": "No members provided"}); sys.exit(1)
            plan = smart_fill_addrgrps(client, args.base_name, members, chunk_size=args.chunk_size, comment=args.comment)
            print_json({"smart_fill": plan})

        elif args.cmd == "attach-grps-to-policy":
            res = attach_groups_to_policy(client, args.policy_id, args.base_name, direction=args.direction)
            print_json(res)

        # ===== Probe =====
        elif args.cmd == "probe":
            results = {}
            try:
                client._req("GET", "/api/v2/monitor/network/arp"); results["monitor_arp"] = {"ok": True}
            except Exception as e:
                results["monitor_arp"] = {"ok": False, "error": str(e)}
            try:
                g = client.list_addrgrps(); results["cmdb_addrgrp"] = {"ok": True, "count": len(g)}
            except Exception as e:
                results["cmdb_addrgrp"] = {"ok": False, "error": str(e)}
            print_json({"probe": results})

        else:
            ap.print_help(); sys.exit(2)

    except requests.exceptions.SSLError as e:
        print_json({"error": "SSL error. Put --insecure BEFORE the subcommand.", "detail": str(e)}); sys.exit(1)
    except requests.exceptions.RequestException as e:
        print_json({"error": "HTTP error", "detail": str(e)}); sys.exit(1)
    except Exception as e:
        print_json({"error": str(e)}); sys.exit(1)

if __name__ == "__main__":
    main()
