from ..adapters.fortigate import FortiGateClient
from ..utils import vip_brief, load_json_arg, suggest_similar, print_json, to_enable_disable

def handle_list_vips(client: FortiGateClient, args):
    vips = client.list_vips()
    print_json({"vips": [vip_brief(v) for v in vips], "count": len(vips)})

def handle_search_vips(client: FortiGateClient, args):
    q = args.q
    names = [v.get("name") for v in client.list_vips() if v.get("name")]
    matchs = [n for n in names if q.lower() in n.lower()] or suggest_similar(q, names)
    print_json({"query": q, "matches": matchs, "count": len(matchs)})

def handle_get_vip(client: FortiGateClient, args):
    v = client.get_vip(args.name)
    if not v:
        names_all = [x.get("name") for x in client.list_vips() if x.get("name")]
        print_json({"error": f"VIP '{args.name}' not found", "suggestions": suggest_similar(args.name, names_all)}); return 1
    print_json({"vip": v, "brief": vip_brief(v)})

def handle_create_vip(client: FortiGateClient, args):
    payload = load_json_arg(args.data)
    out = client.create_vip(payload)
    print_json({"created": out, "brief": vip_brief(out)})

def handle_create_vip_simple(client: FortiGateClient, args):
    body = {
        "name": args.name,
        "extip": args.extip,
        "mappedip": args.mappedip,
        "type": "static-nat",
    }
    if args.extintf: body["extintf"] = args.extintf
    if args.comment: body["comment"] = args.comment
    out = client.create_vip(body)
    print_json({"created": out, "brief": vip_brief(out)})

def handle_create_vip_portforward(client: FortiGateClient, args):
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

def handle_update_vip(client: FortiGateClient, args):
    payload = load_json_arg(args.data)
    out = client.update_vip(args.name, payload)
    print_json({"updated": out, "brief": vip_brief(out)})

def handle_update_vip_fields(client: FortiGateClient, args):
    body = {}
    if args.extip is not None: body["extip"] = args.extip
    if args.mappedip is not None: body["mappedip"] = args.mappedip
    if args.extintf is not None: body["extintf"] = args.extintf
    if args.portforward is not None: body["portforward"] = to_enable_disable(args.portforward)
    if args.protocol is not None: body["protocol"] = args.protocol
    if args.extport is not None: body["extport"] = str(args.extport)
    if args.mappedport is not None: body["mappedport"] = str(args.mappedport)
    if args.comment is not None: body["comment"] = args.comment
    out = client.update_vip(args.name, body)
    print_json({"updated": out, "brief": vip_brief(out)})

def handle_delete_vip(client: FortiGateClient, args):
    client.delete_vip(args.name)
    print_json({"deleted": args.name})

def register(subparsers):
    subparsers.add_parser("list-vips", help="List virtual IPs (firewall/vip)").set_defaults(_handler=handle_list_vips)

    sv = subparsers.add_parser("search-vips", help="Search VIPs by name substring")
    sv.add_argument("--q", required=True)
    sv.set_defaults(_handler=handle_search_vips)

    gv = subparsers.add_parser("get-vip", help="Get VIP by name")
    gv.add_argument("--name", required=True)
    gv.set_defaults(_handler=handle_get_vip)

    cv = subparsers.add_parser("create-vip", help="Create VIP (JSON or @file.json)")
    cv.add_argument("--data", required=True)
    cv.set_defaults(_handler=handle_create_vip)

    cvs = subparsers.add_parser("create-vip-simple", help="Create 1:1 static NAT VIP (no JSON)")
    cvs.add_argument("--name", required=True)
    cvs.add_argument("--extip", required=True)
    cvs.add_argument("--mappedip", required=True)
    cvs.add_argument("--extintf", default=None)
    cvs.add_argument("--comment", default=None)
    cvs.set_defaults(_handler=handle_create_vip_simple)

    cvp = subparsers.add_parser("create-vip-portforward", help="Create port-forward VIP (no JSON)")
    cvp.add_argument("--name", required=True)
    cvp.add_argument("--extip", required=True)
    cvp.add_argument("--mappedip", required=True)
    cvp.add_argument("--protocol", choices=["tcp","udp","sctp"], required=True)
    cvp.add_argument("--extport", required=True)
    cvp.add_argument("--mappedport", required=True)
    cvp.add_argument("--extintf", default=None)
    cvp.add_argument("--comment", default=None)
    cvp.set_defaults(_handler=handle_create_vip_portforward)

    uv = subparsers.add_parser("update-vip", help="Update VIP by name (JSON or @file.json)")
    uv.add_argument("--name", required=True)
    uv.add_argument("--data", required=True)
    uv.set_defaults(_handler=handle_update_vip)

    uvf = subparsers.add_parser("update-vip-fields", help="Update VIP fields (no JSON)")
    uvf.add_argument("--name", required=True)
    uvf.add_argument("--extip", default=None)
    uvf.add_argument("--mappedip", default=None)
    uvf.add_argument("--extintf", default=None)
    uvf.add_argument("--portforward", default=None, help="enable/disable/true/false")
    uvf.add_argument("--protocol", default=None, choices=["tcp","udp","sctp"])
    uvf.add_argument("--extport", default=None)
    uvf.add_argument("--mappedport", default=None)
    uvf.add_argument("--comment", default=None)
    uvf.set_defaults(_handler=handle_update_vip_fields)

    dv = subparsers.add_parser("delete-vip", help="Delete VIP by name")
    dv.add_argument("--name", required=True)
    dv.set_defaults(_handler=handle_delete_vip)

