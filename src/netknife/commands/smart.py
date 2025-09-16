from ..adapters.fortigate import FortiGateClient
from ..utils import names, match_base_groups, print_json

def smart_fill_addrgrps(client: FortiGateClient, base_name: str, new_members, chunk_size: int = 255, comment=None):
    groups = client.list_addrgrps()
    base_groups = match_base_groups(groups, base_name)

    present = []
    group_info = {}
    for gname, _ in base_groups:
        g = client.get_addrgrp(gname)
        mems = names(g.get("member")) if g else []
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
            updated_groups.append({"name": gname, "added": take, "new_count": len(names(out.get("member")))})
            to_add = to_add[capacity:]

    next_idx = max([idx for _, idx in base_groups]) + 1 if base_groups else 1
    while to_add:
        batch = to_add[:chunk_size]
        gname = base_name if next_idx == 1 else f"{base_name}-{next_idx}"
        if next_idx != 1:
            client.create_addrgrp(gname, members=[], comment=comment)
        out = client.add_members_to_addrgrp(gname, batch) if batch else client.get_addrgrp(gname)
        created_groups.append({"name": gname, "added": batch, "new_count": len(names(out.get("member")))})
        to_add = to_add[chunk_size:]
        next_idx += 1

    return {
        "base": base_name,
        "chunk_size": chunk_size,
        "created_groups": created_groups,
        "updated_groups": updated_groups,
        "skipped_existing": len(new_members) - (sum(len(x["added"]) for x in created_groups)+sum(len(x["added"]) for x in updated_groups)),
    }

def attach_groups_to_policy(client: FortiGateClient, policy_id: int, base_name: str, direction: str = "dst"):
    direction = direction.lower()
    if direction not in ("src", "dst"):
        raise RuntimeError("direction must be 'src' or 'dst'")
    groups = client.list_addrgrps()
    base_groups = match_base_groups(groups, base_name)
    names_list = [g for g, _ in base_groups]
    if not names_list:
        raise RuntimeError(f"No groups found for base '{base_name}'")
    if direction == "src":
        out = client.update_policy_addrs(policy_id, add_src=names_list)
    else:
        out = client.update_policy_addrs(policy_id, add_dst=names_list)
    from ..utils import pick_policy_fields
    return {"policy": pick_policy_fields(out), "attached_groups": names_list, "direction": direction}

def handle_smart_fill_addrgrps(client: FortiGateClient, args):
    members = [x.strip() for x in (args.members or "").split(",") if x.strip()]
    if args.members_file:
        with open(args.members_file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    members.append(s)
    if not members:
        print_json({"error": "No members provided"}); return 1
    plan = smart_fill_addrgrps(client, args.base_name, members, chunk_size=args.chunk_size, comment=args.comment)
    print_json({"smart_fill": plan})

def handle_attach_grps_to_policy(client: FortiGateClient, args):
    res = attach_groups_to_policy(client, args.policy_id, args.base_name, direction=args.direction)
    print_json(res)

def register(subparsers):
    sc = subparsers.add_parser("smart-fill-addrgrps", help="Spread members across groups with <= chunk-size; auto-create -2/-3...")
    sc.add_argument("--base-name", required=True)
    sc.add_argument("--members", default="")
    sc.add_argument("--members-file", default=None)
    sc.add_argument("--chunk-size", type=int, default=255)
    sc.add_argument("--comment", default=None)
    sc.set_defaults(_handler=handle_smart_fill_addrgrps)

    at = subparsers.add_parser("attach-grps-to-policy", help="Attach base-name groups to a policy (src or dst)")
    at.add_argument("--policy-id", type=int, required=True)
    at.add_argument("--base-name", required=True)
    at.add_argument("--direction", choices=["src","dst"], default="dst")
    at.set_defaults(_handler=handle_attach_grps_to_policy)

