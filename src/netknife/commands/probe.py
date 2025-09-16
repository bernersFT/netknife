from ..adapters.fortigate import FortiGateClient
from ..utils import print_json

def handle_probe(client: FortiGateClient, args):
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

def register(subparsers):
    pr = subparsers.add_parser("probe", help="Connectivity probe for monitor+cmdb endpoints")
    pr.set_defaults(_handler=handle_probe)

