from ..adapters.fortigate import FortiGateClient
from ..utils import names, suggest_similar, print_json

def handle_list_addrgrps(client: FortiGateClient, args):
    groups = client.list_addrgrps()
    out = []
    for g in groups:
        mems = names(g.get("member"))
        out.append({"name": g.get("name"), "members": mems, "count": len(mems), "comment": g.get("comment")})
    print_json({"addrgrps": out})

def handle_search_addrgrps(client: FortiGateClient, args):
    q = args.q
    groups = client.list_addrgrps()
    gnames = [g.get("name") for g in groups if g.get("name")]
    matchs = [n for n in gnames if q.lower() in n.lower()] or suggest_similar(q, gnames)
    print_json({"query": q, "matches": matchs, "count": len(matchs)})

def handle_get_addrgrp(client: FortiGateClient, args):
    g = client.get_addrgrp(args.name)
    if not g:
        groups = client.list_addrgrps()
        names_all = [x.get("name") for x in groups if x.get("name")]
        print_json({"error": f"Addrgrp '{args.name}' not found", "suggestions": suggest_similar(args.name, names_all)}); return 1
    mems = names(g.get("member"))
    print_json({"addrgrp": {"name": g.get("name"), "members": mems, "count": len(mems), "comment": g.get("comment"), "uuid": g.get("uuid")}})

def handle_create_addrgrp(client: FortiGateClient, args):
    members = [x.strip() for x in (args.members or "").split(",") if x.strip()]
    if members and not args.skip_validate_members:
        not_found = [m for m in members if not client.object_exists(m)]
        if not_found:
            print_json({"error": "Some members do not exist (address/addrgrp)", "not_found": not_found}); return 1
    out = client.create_addrgrp(args.name, members=members, comment=args.comment)
    print_json({"created": out})

def handle_update_addrgrp(client: FortiGateClient, args):
    members = None if args.members is None else [x.strip() for x in args.members.split(",") if x.strip()]
    if members is not None and members and not args.skip_validate_members:
        not_found = [m for m in members if not client.object_exists(m)]
        if not_found:
            print_json({"error": "Some members do not exist (address/addrgrp)", "not_found": not_found}); return 1
    out = client.update_addrgrp(args.name, new_name=args.new_name, members=members, comment=args.comment)
    print_json({"updated": out})

def handle_add_to_addrgrp(client: FortiGateClient, args):
    members = [x.strip() for x in args.members.split(",") if x.strip()]
    if members and not args.skip_validate_members:
        not_found = [m for m in members if not client.object_exists(m)]
        if not_found:
            print_json({"error": "Some members do not exist (address/addrgrp)", "not_found": not_found}); return 1
    out = client.add_members_to_addrgrp(args.name, members)
    print_json({"updated": out, "count": len(names(out.get("member")))})

def handle_remove_from_addrgrp(client: FortiGateClient, args):
    members = [x.strip() for x in args.members.split(",") if x.strip()]
    out = client.remove_members_from_addrgrp(args.name, members)
    print_json({"updated": out, "count": len(names(out.get("member")))})

def handle_delete_addrgrp(client: FortiGateClient, args):
    client.delete_addrgrp(args.name)
    print_json({"deleted": args.name})

def handle_find_groups_with_member(client: FortiGateClient, args):
    n = args.name
    grps = []
    for g in client.list_addrgrps():
        mems = names(g.get("member"))
        if n in mems:
            grps.append({"name": g.get("name"), "count": len(mems)})
    print_json({"name": n, "groups": grps, "count": len(grps)})

def register(subparsers):
    subparsers.add_parser("list-addrgrps", help="List address-groups").set_defaults(_handler=handle_list_addrgrps)

    sg = subparsers.add_parser("search-addrgrps", help="Search addrgrps by substring")
    sg.add_argument("--q", required=True)
    sg.set_defaults(_handler=handle_search_addrgrps)

    gg = subparsers.add_parser("get-addrgrp", help="Get addrgrp by name")
    gg.add_argument("--name", required=True)
    gg.set_defaults(_handler=handle_get_addrgrp)

    cg = subparsers.add_parser("create-addrgrp", help="Create addrgrp")
    cg.add_argument("--name", required=True)
    cg.add_argument("--members", default="")
    cg.add_argument("--comment", default=None)
    cg.add_argument("--skip-validate-members", action="store_true")
    cg.set_defaults(_handler=handle_create_addrgrp)

    ug = subparsers.add_parser("update-addrgrp", help="Replace addrgrp fields/members")
    ug.add_argument("--name", required=True)
    ug.add_argument("--new-name", default=None)
    ug.add_argument("--members", default=None)
    ug.add_argument("--comment", default=None)
    ug.add_argument("--skip-validate-members", action="store_true")
    ug.set_defaults(_handler=handle_update_addrgrp)

    ag = subparsers.add_parser("add-to-addrgrp", help="Add members to addrgrp (idempotent)")
    ag.add_argument("--name", required=True)
    ag.add_argument("--members", required=True)
    ag.add_argument("--skip-validate-members", action="store_true")
    ag.set_defaults(_handler=handle_add_to_addrgrp)

    rg = subparsers.add_parser("remove-from-addrgrp", help="Remove members from addrgrp")
    rg.add_argument("--name", required=True)
    rg.add_argument("--members", required=True)
    rg.set_defaults(_handler=handle_remove_from_addrgrp)

    dg = subparsers.add_parser("delete-addrgrp", help="Delete addrgrp by name")
    dg.add_argument("--name", required=True)
    dg.set_defaults(_handler=handle_delete_addrgrp)

    fgm = subparsers.add_parser("find-groups-with-member", help="Find addrgrps containing a given object")
    fgm.add_argument("--name", required=True)
    fgm.set_defaults(_handler=handle_find_groups_with_member)

