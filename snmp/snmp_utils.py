import subprocess
import shlex
import re
from typing import Dict, List, Tuple, Optional


# ============================================================
#                   Low-level SNMP wrappers
# ============================================================

def run_snmpwalk(host: str,
                 community: str,
                 oid: str,
                 timeout: int = 2,
                 retries: int = 1) -> str:
    """
    اجرای snmpwalk و برگرداندن خروجی به صورت رشته (stdout).
    """
    cmd = f"snmpwalk -v2c -c {community} -t {timeout} -r {retries} {host} {oid}"
    proc = subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout or ""


def run_snmpget(host: str,
                community: str,
                oid: str,
                timeout: int = 2,
                retries: int = 1) -> str:
    """
    اجرای snmpget و برگرداندن خروجی به صورت رشته (stdout).
    """
    cmd = f"snmpget -v2c -c {community} -t {timeout} -r {retries} {host} {oid}"
    proc = subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout or ""


# ============================================================
#        Helpers قدیمی برای parse خروجی snmpwalk/snmpget
#   (برای سازگاری با snmp_host.py و snmp_sw.py فعلی تو)
# ============================================================

def parse_snmp_line(line: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse one line of snmpwalk/snmpget output.

    Returns:
        (oid, type, value) or None if line is not a standard SNMP data line.

    Examples:
        IF-MIB::ifDescr.10152 = STRING: GigabitEthernet1/0/48
        iso.3.6.1.2.1.17.4.3.1.2.0.64.140.234.2.85 = INTEGER: 52
        iso.3.6.1.2.1.1.5.0 = STRING: "sw01.domain.local"
        SNMPv2-SMI::mib-2.1.1.0 = Timeticks: (123456) 0:20:34.56
    """
    line = line.strip()
    if not line:
        return None

    # skip errors / non-data lines
    if (
        "No Such" in line
        or "Timeout" in line
        or "End of MIB" in line
        or line.startswith("Error:")
    ):
        return None

    # common form: <oid> = <TYPE>: <value>
    m = re.match(
        r'(?P<oid>[^\s]+)\s*=\s*(?P<type>[A-Za-z0-9\-]+)\s*:\s*(?P<value>.*)$',
        line
    )
    if not m:
        # fallback: <oid> = <value> (type omitted)
        m2 = re.match(r'(?P<oid>[^\s]+)\s*=\s*(?P<value>.*)$', line)
        if not m2:
            return None
        oid = m2.group("oid").strip()
        typ = ""
        val = m2.group("value").strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        return oid, typ, val

    oid = m.group("oid").strip()
    typ = m.group("type").strip()
    val = m.group("value").strip()

    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]

    return oid, typ, val



def oid_last_index(oid: str) -> Optional[str]:
    """
    آخرین index یک OID را برمی‌گرداند.

    مثال:
        'iso.3.6.1.2.1.2.2.1.2.10152' -> '10152'
        'IF-MIB::ifDescr.10152' -> '10152'
    """
    if not oid:
        return None

    # اگر :: داشت (IF-MIB::ifDescr.10152)
    if '::' in oid:
        _, rest = oid.split('::', 1)
        parts = rest.split('.')
        return parts[-1] if parts else None

    # حالت iso.3.6.1...
    parts = oid.split('.')
    return parts[-1] if parts else None


def pretty_mac(mac: str) -> str:
    """
    MAC را به فرم استاندارد lowercase colon-separated برمی‌گرداند.
    مثال ورودی: 'D4-F5-EF-95-FD-70' یا 'd4:f5:ef:95:fd:70'
    خروجی:      'd4:f5:ef:95:fd:70'
    """
    return normalize_mac(mac)


# ============================================================
#          Helpers: MAC handling + OID MAC index parsing
# ============================================================

def normalize_mac(mac: str) -> str:
    """
    MAC را به فرم استاندارد lowercase colon-separated برمی‌گرداند.
    """
    mac = mac.strip().lower()
    mac = mac.replace('-', ':')
    if ':' not in mac and len(mac) == 12:
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    return mac


def _parse_mac_from_oid_suffix(oid_suffix: str) -> Optional[str]:
    """
    ورودی: '0.64.140.234.2.85' -> خروجی: '00:40:8c:ea:02:55'
    (6 octet آخر index FDB در dot1dTpFdbPort)

    اگر طول index غیر 6 بود، None برمی‌گرداند.
    """
    parts = [p for p in oid_suffix.split('.') if p != '']
    if len(parts) != 6:
        return None
    try:
        bytes_ = [int(x) for x in parts]
    except ValueError:
        return None
    return ':'.join(f"{b:02x}" for b in bytes_)


# ============================================================
#             Bridge-MIB / FDB کلاسیک (dot1dTpFdbPort)
# ============================================================

def get_fdb_table(host: str, community: str) -> Dict[str, int]:
    """
    FDB کلاسیک را از dot1dTpFdbPort می‌خواند.

    OID: 1.3.6.1.2.1.17.4.3.1.2

    خروجی:
        dict:
            key: MAC به فرم 'd4:f5:ef:95:fd:70'
            val: bridge_port (int)

    مثال خط خروجی snmpwalk:
        iso.3.6.1.2.1.17.4.3.1.2.0.64.140.234.2.85 = INTEGER: 52
    """
    oid = "1.3.6.1.2.1.17.4.3.1.2"
    output = run_snmpwalk(host, community, oid)
    mac_to_bridge: Dict[str, int] = {}

    pattern = re.compile(
        r".*17\.4\.3\.1\.2\.(?P<idx>[\d\.]+)\s+\=\s+INTEGER:\s+(?P<port>\d+)"
    )

    for line in output.splitlines():
        line = line.strip()
        if not line or "No Such" in line:
            continue
        m = pattern.match(line)
        if not m:
            continue

        idx = m.group("idx")
        port = int(m.group("port"))
        mac = _parse_mac_from_oid_suffix(idx)
        if not mac:
            continue

        mac_norm = normalize_mac(mac)
        mac_to_bridge[mac_norm] = port

    return mac_to_bridge


def get_bridge_port_ifindex_map(host: str, community: str) -> Dict[int, int]:
    """
    نگاشت Bridge Port به ifIndex را از dot1dBasePortIfIndex می‌گیرد.

    OID: 1.3.6.1.2.1.17.1.4.1.2

    خروجی:
        dict:
            key: bridge_port (int)
            val: ifIndex (int)

    مثال خط:
        iso.3.6.1.2.1.17.1.4.1.2.52 = INTEGER: 10152
    """
    oid = "1.3.6.1.2.1.17.1.4.1.2"
    output = run_snmpwalk(host, community, oid)
    bp_to_ifindex: Dict[int, int] = {}

    pattern = re.compile(
        r".*17\.1\.4\.1\.2\.(?P<bp>\d+)\s+\=\s+INTEGER:\s+(?P<ifidx>\d+)"
    )

    for line in output.splitlines():
        line = line.strip()
        if not line or "No Such" in line:
            continue
        m = pattern.match(line)
        if not m:
            continue

        bp = int(m.group("bp"))
        ifidx = int(m.group("ifidx"))
        bp_to_ifindex[bp] = ifidx

    return bp_to_ifindex


# ============================================================
#                  IF-MIB helpers (ports)
# ============================================================

def get_ifindex_name_map(host: str,
                         community: str) -> Dict[int, str]:
    """
    نگاشت ifIndex به نام رابط (interface name) را برمی‌گرداند.

    ابتدا ifName (1.3.6.1.2.1.31.1.1.1.1) را می‌خواند،
    اگر برای برخی ifIndex ها name نبود، از ifDescr (1.3.6.1.2.1.2.2.1.2) استفاده می‌کند.

    خروجی:
        dict:
            key: ifIndex (int)
            val: interface name (str)
    """
    ifname_oid = "1.3.6.1.2.1.31.1.1.1.1"
    ifdescr_oid = "1.3.6.1.2.1.2.2.1.2"

    mapping: Dict[int, str] = {}

    # --- ifName ---
    out_ifname = run_snmpwalk(host, community, ifname_oid)
    # نمونه خط:
    # IF-MIB::ifName.10152 = STRING: Gi1/0/48
    pattern = re.compile(
        r".*\.(?P<ifidx>\d+)\s+\=\s+\w+:\s+(?P<name>.+)"
    )
    for line in out_ifname.splitlines():
        line = line.strip()
        if not line or "No Such" in line:
            continue
        m = pattern.match(line)
        if not m:
            continue
        ifidx = int(m.group("ifidx"))
        name = m.group("name").strip().strip('"')
        mapping[ifidx] = name

    # --- ifDescr (fallback) ---
    out_descr = run_snmpwalk(host, community, ifdescr_oid)
    # IF-MIB::ifDescr.10152 = STRING: GigabitEthernet1/0/48
    for line in out_descr.splitlines():
        line = line.strip()
        if not line or "No Such" in line:
            continue
        m = pattern.match(line)
        if not m:
            continue
        ifidx = int(m.group("ifidx"))
        if ifidx in mapping:
            continue
        name = m.group("name").strip().strip('"')
        mapping[ifidx] = name

    return mapping


# ============================================================
#           High-level map: MAC -> (bridge_port, ifIndex, ifName)
# ============================================================

def build_mac_to_port_map(host: str,
                          community: str) -> Dict[str, Tuple[int, int, str]]:
    """
    یک map جامع برمی‌گرداند:
        MAC -> (bridge_port, ifIndex, ifName)

    اگر ifName برای ifIndex خاصی وجود نداشت، رشته خالی برمی‌گردد.
    """
    fdb = get_fdb_table(host, community)                        # mac -> bridge_port
    bp_to_ifindex = get_bridge_port_ifindex_map(host, community)  # bp -> ifIndex
    ifindex_to_name = get_ifindex_name_map(host, community)       # ifIndex -> name

    result: Dict[str, Tuple[int, int, str]] = {}

    for mac, bp in fdb.items():
        ifidx = bp_to_ifindex.get(bp)
        if ifidx is None:
            result[mac] = (bp, -1, "")
            continue
        name = ifindex_to_name.get(ifidx, "")
        result[mac] = (bp, ifidx, name)

    return result

def pretty_mac(mac: str) -> str:
         """
         Normalize MAC to lowercase colon-separated form.
         """
         mac = mac.replace("-", ":").lower()
         parts = mac.split(":")
         parts = [p.zfill(2) for p in parts]
         return ":".join(parts)
