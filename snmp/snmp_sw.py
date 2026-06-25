#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Optional, List, Any

from snmp_utils import (
    normalize_mac,
    get_fdb_table,
    get_bridge_port_ifindex_map,
    get_ifindex_name_map,
)


def discover_switch(
    switch_ip: str,
    community: str,
) -> Dict[str, Any]:
    """
    کشف اطلاعات سوئیچ شامل FDB و پورت‌ها.

    ورودی:
        switch_ip : IP سوئیچ
        community : SNMP community

    خروجی:
        dict با ساختار:
        {
            "ip": ...,
            "name": ...,
            "fdb": [
                {
                    "mac": ...,
                    "vlan": ...,
                    "if_index": ...,
                    "if_name": ...
                },
                ...
            ],
            "vlans": {}
        }
    """
    fdb = get_fdb_table(switch_ip, community)
    bp_to_ifindex = get_bridge_port_ifindex_map(switch_ip, community)
    ifindex_to_name = get_ifindex_name_map(switch_ip, community)

    fdb_entries: List[Dict[str, Any]] = []

    for mac, bridge_port in fdb.items():
        if_index = bp_to_ifindex.get(bridge_port, -1)
        if_name = ifindex_to_name.get(if_index, "")
        
        entry = {
            "mac": mac,
            "vlan": "-",
            "if_index": if_index,
            "if_name": if_name,
        }
        fdb_entries.append(entry)

    return {
        "ip": switch_ip,
        "name": switch_ip,
        "fdb": fdb_entries,
        "vlans": {}
    }


def discover_switch_vlans(
    switch_ip: str,
    community: str,
) -> Dict[str, str]:
    """
    کشف VLAN‌ها (فعلاً placeholder).

    خروجی:
        dict خالی یا نگاشت‌های VLAN.
    """
    return {}