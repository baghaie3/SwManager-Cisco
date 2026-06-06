import asyncio
from puresnmp import Client, V2C

OID_SYSNAME   = "1.3.6.1.2.1.1.5.0"
OID_LLDP_REM  = "1.0.8802.1.1.2.1.4.1.1"
OID_CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1"

LLDP_REM_PORT_ID   = 7
LLDP_REM_SYSNAME   = 9
CDP_CACHE_DEVICEID = 6
CDP_CACHE_ADDRESS  = 4
CDP_CACHE_PORT     = 7


class SimpleProfile:
    def __init__(self, community="public"):
        self.community = community

    def get_snmp_community(self) -> bytes:
        c = self.community
        return c if isinstance(c, bytes) else c.encode()


def snmp_get(ip: str, oid: str, profile):
    async def _():
        client = Client(ip, V2C(profile.get_snmp_community()))
        return await client.get(oid)
    try:
        return str(asyncio.run(_()))
    except Exception as e:
        print(f"[snmp_get ERROR] {e}")
        return None


def snmp_walk(ip: str, oid: str, profile):
    async def _():
        out = []
        client = Client(ip, V2C(profile.get_snmp_community()))
        async for item in client.walk(oid):
            out.append((str(item.oid), str(item.value)))
        return out
    try:
        return asyncio.run(_())
    except Exception as e:
        print(f"[snmp_walk ERROR] {e}")
        return []


def get_sysname(ip, profile):
    return snmp_get(ip, OID_SYSNAME, profile)


def get_lldp_neighbors(ip, profile):
    rows = snmp_walk(ip, OID_LLDP_REM, profile)
    neighbors = {}
    for oid_str, value in rows:
        parts = oid_str.split(".")
        try:
            col        = int(parts[-3])
            local_port = parts[-2]
            rem_index  = parts[-1]
        except Exception:
            continue
        key = (local_port, rem_index)
        if key not in neighbors:
            neighbors[key] = {"local_port": local_port}
        if col == LLDP_REM_PORT_ID:
            neighbors[key]["remote_port"] = value
        elif col == LLDP_REM_SYSNAME:
            neighbors[key]["remote_sysname"] = value
    return [n for n in neighbors.values() if "remote_sysname" in n]


def get_cdp_neighbors(ip, profile):
    rows = snmp_walk(ip, OID_CDP_CACHE, profile)
    neighbors = {}
    for oid_str, value in rows:
        parts = oid_str.split(".")
        try:
            col         = int(parts[-3])
            local_port  = parts[-2]
            cache_index = parts[-1]
        except Exception:
            continue
        key = (local_port, cache_index)
        if key not in neighbors:
            neighbors[key] = {"local_port": local_port}
        if col == CDP_CACHE_DEVICEID:
            neighbors[key]["remote_sysname"] = value
        elif col == CDP_CACHE_ADDRESS:
            neighbors[key]["remote_ip"] = value
        elif col == CDP_CACHE_PORT:
            neighbors[key]["remote_port"] = value
    return [n for n in neighbors.values() if "remote_sysname" in n]
