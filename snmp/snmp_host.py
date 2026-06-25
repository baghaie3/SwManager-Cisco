# snmp_host.py

import logging
from typing import Dict, List, Optional

from snmp_utils import (
    run_snmpwalk,
    parse_snmp_line,
    normalize_mac,
)

logger = logging.getLogger(__name__)


class EsxiHostInfo:
    def __init__(self, ip: str):
        self.ip = ip
        self.name: Optional[str] = None
        # mac -> interface name, only physical vmnics
        self.mac_table: Dict[str, str] = {}
        self.raw_snmp: List[str] = []

    def __repr__(self) -> str:
        return f"<EsxiHostInfo ip={self.ip}, name={self.name}, macs={len(self.mac_table)}>"


def discover_esxi_host(
    host_ip: str,
    snmp_community: str,
    mac_table_oid: Optional[str] = None,
    hostname_oid: Optional[str] = None,
) -> EsxiHostInfo:
    """
    Discover ESXi host VMNIC MAC addresses (physical interfaces only).
    Uses IF-MIB ifPhysAddress (.1.3.6.1.2.1.2.2.1.6) and ifDescr (.1.3.6.1.2.1.2.2.1.2)
    """
    logger.info("Starting ESXi discovery for host %s", host_ip)
    host_info = EsxiHostInfo(ip=host_ip)

    # --- Hostname ---
    if hostname_oid:
        logger.debug("Querying hostname for %s with OID %s", host_ip, hostname_oid)
        try:
            out = run_snmpwalk(host_ip, snmp_community, hostname_oid)
        except Exception as exc:
            logger.error("Hostname query failed: %s", exc)
            out = ""
        for line in out.splitlines():
            host_info.raw_snmp.append(line)
            parsed = parse_snmp_line(line)
            if parsed:
                _, _, value = parsed
                host_info.name = value.strip('"')
                break
        logger.info("Hostname: %s", host_info.name)

    # --- MAC addresses ---
    if not mac_table_oid:
        if_phys_addr_oid = "1.3.6.1.2.1.2.2.1.6"
        if_descr_oid = "1.3.6.1.2.1.2.2.1.2"

        try:
            mac_out = run_snmpwalk(host_ip, snmp_community, if_phys_addr_oid)
        except Exception as exc:
            logger.error("Failed to query ifPhysAddress: %s", exc)
            mac_out = ""

        mac_by_index: Dict[int, str] = {}
        for line in mac_out.splitlines():
            host_info.raw_snmp.append(line)
            parsed = parse_snmp_line(line)
            if not parsed:
                continue
            oid, typ, value = parsed
            idx_str = oid.split(".")[-1]
            if not idx_str.isdigit():
                continue
            if_index = int(idx_str)
            mac = _extract_mac_from_hex_string(value, typ)
            if mac:
                mac_by_index[if_index] = mac

        try:
            name_out = run_snmpwalk(host_ip, snmp_community, if_descr_oid)
        except Exception as exc:
            logger.error("Failed to query ifDescr: %s", exc)
            name_out = ""

        index_to_name: Dict[int, str] = {}
        for line in name_out.splitlines():
            host_info.raw_snmp.append(line)
            parsed = parse_snmp_line(line)
            if not parsed:
                continue
            oid, _, name_val = parsed
            idx_str = oid.split(".")[-1]
            if not idx_str.isdigit():
                continue
            if_index = int(idx_str)
            # نگه‌داری فقط اینترفیس‌های فیزیکی (حاوی "vmnic")
            if_name = name_val.strip('"')
            if "vmnic" in if_name.lower():
                index_to_name[if_index] = if_name

        # ساخت mac_table فقط برای اینترفیس‌های فیلترشده
        for idx, mac in mac_by_index.items():
            if idx in index_to_name:
                host_info.mac_table[mac] = index_to_name[idx]

    else:
        logger.debug("Using custom OID %s for MAC discovery", mac_table_oid)
        try:
            mac_out = run_snmpwalk(host_ip, snmp_community, mac_table_oid)
        except Exception as exc:
            logger.error("Custom MAC OID query failed: %s", exc)
            mac_out = ""

        for line in mac_out.splitlines():
            host_info.raw_snmp.append(line)
            parsed = parse_snmp_line(line)
            if not parsed:
                continue
            oid, typ, value = parsed
            mac = _extract_mac_from_hex_string(value, typ)
            if mac:
                host_info.mac_table[mac] = oid  # fallback

    logger.info("Discovered %d physical MAC(s)", len(host_info.mac_table))
    return host_info

def _extract_mac_from_hex_string(value: str, typ: str) -> Optional[str]:
    """Extract MAC from a Hex-STRING or similar type. Returns normalized MAC or None."""
    value = value.strip().strip('"')
    if typ.lower().startswith("hex-string"):
        bytes_str = value.split()
        if len(bytes_str) == 6 and all(len(b) <= 2 for b in bytes_str):
            try:
                mac_bytes = [int(b, 16) for b in bytes_str]
                return normalize_mac(":".join(f"{b:02x}" for b in mac_bytes))
            except ValueError:
                return None
    # also try plain string if it looks like MAC
    return _extract_mac_generic(value)


def _extract_mac_generic(value: str) -> Optional[str]:
    """Fallback MAC parsing from colon/period/dash formats."""
    value = value.strip()
    if not value:
        return None
    # already normalized?
    if ":" in value or "-" in value:
        return normalize_mac(value)
    # Cisco style
    if "." in value and len(value.replace(".", "")) == 12:
        raw = value.replace(".", "")
        try:
            int(raw, 16)
            return normalize_mac(":".join(raw[i:i+2] for i in range(0,12,2)))
        except ValueError:
            return None
    return None