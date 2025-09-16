from typing import Any, Dict
from ..adapters.fortigate import FortiGateClient
from ..utils import load_json_arg, wrap_names, names, pick_policy_fields, print_json

def _created(out: Dict[str, Any]):
    print_json({"created": pick_policy_fields(out) if isinstance(out, dict) else out})

def _updated(out: Dict[str, Any]):
    print_json({"updated": pick_policy_fields(out) if isinstance(out, dict) else out})

def handle_policy_id(client: FortiGateClient, args):
    p = client.get_policy_by_id(args.policy_id)
    if not p:
        print_json({"error": f"Policy {args.policy_id} not found"}); return 1
    print_json({"policy": pick_policy_fields(p)})

def handle_policy_name(client: FortiGateClient, args):
    p = client.get_policy_by_name(args.policy_name)
    if not p:
        print_json({"error": f"Policy '{args.policy_name}' not found"}); return 1
    print_json({"policy": pick_policy_fields(p)})

def handle_find_policies_with(client: FortiGateClient, args):
    res = []
    for p in client.list_policies():
        if args.object_name in names(p.get("srcaddr")) or args.object_name in names(p.get("dstaddr")):
            res.append(pick_policy_fields(p))
    print_json({"referencing_policies": res, "count": len(res)})

def handle_search_policies(client: FortiGateClient, args):
    q = args.q.lower()
    res = []
    for p in client.list_policies():
        if q in str(p.get("name") or "").lower():
            res.append(pick_policy_fields(p))
    print_json({"query": args.q, "matches": res, "count": len(res)})

def handle_create_policy(client: FortiGateClient, args):
    payload = load_json_arg(args.data)
    out = client.create_policy(payload)
    _created(out)

def handle_create_policy_simple(client: FortiGateClient, args):
    payload = {
        "name": args.name,
        "srcintf": wrap_names([x.strip() for x in args.srcintf.split(",") if x.strip()]),
        "dstintf": wrap_names([x.strip() for x in args.dstintf.split(",") if x.strip()]),
        "srcaddr": wrap_names([x.strip() for x in args.srcaddr.split(",") if x.strip()]),
        "dstaddr": wrap_names([x.strip() for x in args.dstaddr.split(",") if x.strip()]),
        "service": wrap_names([x.strip() for x in args.service.split(",") if x.strip()]),
        "action": args.action,
        "schedule": args.schedule,
        "status": args.status,
    }
    if args.logtraffic: payload["logtraffic"] = args.logtraffic
    if args.comment: payload["comments"] = args.comment
    if args.nat: payload["nat"] = True
    out = client.create_policy(payload)
    _created(out)

def handle_update_policy(client: FortiGateClient, args):
    payload = load_json_arg(args.data)
    out = client.update_policy(args.policy_id, payload)
    _updated(out)

def handle_update_policy_fields(client: FortiGateClient, args):
    body: Dict[str, Any] = {}
    if args.name is not None: body["name"] = args.name
    if args.srcintf is not None: body["srcintf"] = wrap_names([x.strip() for x in args.srcintf.split(",") if x.strip()])
    if args.dstintf is not None: body["dstintf"] = wrap_names([x.strip() for x in args.dstintf.split(",") if x.strip()])
    if args.srcaddr is not None: body["srcaddr"] = wrap_names([x.strip() for x in args.srcaddr.split(",") if x.strip()])
    if args.dstaddr is not None: body["dstaddr"] = wrap_names([x.strip() for x in args.dstaddr.split(",") if x.strip()])
    if args.service is not None: body["service"] = wrap_names([x.strip() for x in args.service.split(",") if x.strip()])
    if args.action is not None: body["action"] = args.action
    if args.schedule is not None: body["schedule"] = args.schedule
    if args.status is not None: body["status"] = args.status
    if args.nat is not None: body["nat"] = (args.nat == "true")
    if args.logtraffic is not None: body["logtraffic"] = args.logtraffic
    if args.comment is not None: body["comments"] = args.comment
    out = client.update_policy(args.policy_id, body)
    _updated(out)

def handle_policy_set_addrs(client: FortiGateClient, args):
    out = client.update_policy_addrs(
        args.policy_id,
        add_src=[x for x in args.add_src.split(",") if x],
        add_dst=[x for x in args.add_dst.split(",") if x],
        remove_src=[x for x in args.remove_src.split(",") if x],
        remove_dst=[x for x in args.remove_dst.split(",") if x],
    )
    print_json({"policy": pick_policy_fields(out)})

def register(subparsers):
    s1 = subparsers.add_parser("policy-id", help="Inspect policy by ID")
    s1.add_argument("--policy-id", type=int, required=True)
    s1.set_defaults(_handler=handle_policy_id)

    s2 = subparsers.add_parser("policy-name", help="Inspect policy by Name")
    s2.add_argument("--policy-name", required=True)
    s2.set_defaults(_handler=handle_policy_name)

    s3 = subparsers.add_parser("find-policies-with", help="Find policies referencing an object")
    s3.add_argument("--object-name", required=True)
    s3.set_defaults(_handler=handle_find_policies_with)

    sp = subparsers.add_parser("search-policies", help="Search policies by name substring")
    sp.add_argument("--q", required=True)
    sp.set_defaults(_handler=handle_search_policies)

    cp = subparsers.add_parser("create-policy", help="Create policy (JSON or @file.json)")
    cp.add_argument("--data", required=True, help="JSON or @file, payload for /firewall/policy")
    cp.set_defaults(_handler=handle_create_policy)

    cps = subparsers.add_parser("create-policy-simple", help="Create policy without JSON")
    cps.add_argument("--name", required=True)
    cps.add_argument("--srcintf", required=True)
    cps.add_argument("--dstintf", required=True)
    cps.add_argument("--srcaddr", required=True)
    cps.add_argument("--dstaddr", required=True)
    cps.add_argument("--service", default="ALL")
    cps.add_argument("--action", choices=["accept","deny"], default="accept")
    cps.add_argument("--schedule", default="always")
    cps.add_argument("--nat", action="store_true")
    cps.add_argument("--status", choices=["enable","disable"], default="enable")
    cps.add_argument("--logtraffic", choices=["utm","all","disable"], default=None)
    cps.add_argument("--comment", default=None)
    cps.set_defaults(_handler=handle_create_policy_simple)

    up = subparsers.add_parser("update-policy", help="Update policy by ID (JSON or @file.json)")
    up.add_argument("--policy-id", type=int, required=True)
    up.add_argument("--data", required=True)
    up.set_defaults(_handler=handle_update_policy)

    upf = subparsers.add_parser("update-policy-fields", help="Update common policy fields without JSON")
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
    upf.set_defaults(_handler=handle_update_policy_fields)

    pm = subparsers.add_parser("policy-set-addrs", help="Mutate policy srcaddr/dstaddr (add/remove names)")
    pm.add_argument("--policy-id", type=int, required=True)
    pm.add_argument("--add-src", default="")
    pm.add_argument("--add-dst", default="")
    pm.add_argument("--remove-src", default="")
    pm.add_argument("--remove-dst", default="")
    pm.set_defaults(_handler=handle_policy_set_addrs)

