from .policy import register as register_policy
from .address import register as register_address
from .addrgrp import register as register_addrgrp
from .vip import register as register_vip
from .smart import register as register_smart
from .probe import register as register_probe

def register_all(subparsers):
    register_policy(subparsers)
    register_address(subparsers)
    register_addrgrp(subparsers)
    register_vip(subparsers)
    register_smart(subparsers)
    register_probe(subparsers)

