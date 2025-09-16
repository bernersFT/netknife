from ..adapters.fortigate import FortiGateClient
from ..utils import (
    load_json_arg, address_brief, suggest_similar, print_json
)

def handle_list_addresses(client: FortiGateClient, args):
    print_json({"addresses": [address_brief(a) for a in client.list_addresses()]})

def handle_search_addresses(client: FortiGateClient, args):
    q = args.q
    names = [a.get("name") for a in client.list_addresses() if a.get("name")]
    matchs = [n for n in names if q.lower() in n.lower()] or suggest_similar(q, names)
    print_json({"query": q, "matches": matchs, "count": len(matchs)})

def handle_get_address(client: FortiGateClient, args):
    a = client.get_address(args.name)
    if not a:
        names = [x.get("name") for x in client.list_addresses() if x.get("name")]
        print_json({"error": f"Address '{args.name}' not found", "suggestions": suggest_similar(args.name, names)}); return 1
    print_json({"address": a, "brief": address_brief(a)})

def handle_create_address(client: FortiGateClient, args):
    payload = load_json_arg(args.data)
    out = client.create_address(payload)
    print_json({"created": out, "brief": address_brief(out)})

def handle_create_address_ipmask(client: FortiGateClient, args):
    from ..utils import cidr_to_subnet_str
    subnet = cidr_to_subnet_str(args.cidr)
    payload = {"name": args.name, "type": "ipmask", "subnet": subnet}
    if args.comment is not None:
        payload["comment"] = args.comment
    out = client.create_address(payload)
    print_json({"created": out, "brief": address_brief(out)})

def handle_update_address(client: FortiGateClient, args):
    payload = load_json_arg(args.data)
    out = client.update_address(args.name, payload)
    print_json({"updated": out, "brief": address_brief(out)})

def handle_update_address_comment(client: FortiGateClient, args):
    out = client.update_address(args.name, {"comment": args.comment})
    print_json({"updated": out, "brief": address_brief(out)})

def handle_delete_address(client: FortiGateClient, args):
    client.delete_address(args.name)
    print_json({"deleted": args.name})

def register(subparsers):
    subparsers.add_parser("list-addresses", help="List addresses").set_defaults(_handler=handle_list_addresses)

    sa = subparsers.add_parser("search-addresses", help="Search addresses by substring")
    sa.add_argument("--q", required=True)
    sa.set_defaults(_handler=handle_search_addresses)

    ga = subparsers.add_parser("get-address", help="Get address by name")
    ga.add_argument("--name", required=True)
    ga.set_defaults(_handler=handle_get_address)

    ca = subparsers.add_parser("create-address", help="Create address (JSON or @file.json)")
    ca.add_argument("--data", required=True)
    ca.set_defaults(_handler=handle_create_address)

    cai = subparsers.add_parser("create-address-ipmask", help="Create ipmask address without JSON")
    cai.add_argument("--name", required=True)
    cai.add_argument("--cidr", required=True)
    cai.add_argument("--comment", default=None)
    cai.set_defaults(_handler=handle_create_address_ipmask)

    ua = subparsers.add_parser("update-address", help="Update address by name (JSON or @file.json)")
    ua.add_argument("--name", required=True)
    ua.add_argument("--data", required=True)
    ua.set_defaults(_handler=handle_update_address)

    uac = subparsers.add_parser("update-address-comment", help="Update address comment (no JSON)")
    uac.add_argument("--name", required=True)
    uac.add_argument("--comment", required=True)
    uac.set_defaults(_handler=handle_update_address_comment)

    da = subparsers.add_parser("delete-address", help="Delete address by name")
    da.add_argument("--name", required=True)
    da.set_defaults(_handler=handle_delete_address)

