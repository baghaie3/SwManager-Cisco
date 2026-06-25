# snmp_main.py

import json
import os
from typing import Any, Dict, List

from snmp_host import discover_esxi_host
from snmp_sw import discover_switch, discover_switch_vlans
from snmp_db import db

CONFIG_FILE_NAME = "config.json"


def get_script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def load_config() -> Dict[str, Any]:
    cfg_path = os.path.join(get_script_dir(), CONFIG_FILE_NAME)
    with open(cfg_path, "r") as f:
        return json.load(f)


def save_config(config: Dict[str, Any]) -> None:
    cfg_path = os.path.join(get_script_dir(), CONFIG_FILE_NAME)
    with open(cfg_path, "w") as f:
        json.dump(config, f, indent=2)


def correlate(esxi_hosts: List[Dict[str, Any]], switches: List[Dict[str, Any]]) -> Dict[str, Any]:
    mac_index: Dict[str, List[Dict[str, Any]]] = {}

    # جمع‌آوری تمام MACهای سوئیچ‌ها
    for sw in switches:
        sw_name = sw["name"]
        sw_ip = sw["ip"]
        for f in sw.get("fdb", []):
            mac = f.get("mac")
            if not mac:
                continue
            entry = {
                "switch_name": sw_name,
                "switch_ip": sw_ip,
                "vlan": f.get("vlan", "-"),
                "port_if_index": f.get("if_index", ""),
                "port_if_name": f.get("if_name", ""),
            }
            mac_index.setdefault(mac, []).append(entry)

    # DEBUG: نمایش چند MAC اول سوئیچ‌ها
    print("\n🔎 First 5 switch MACs in FDB:")
    for i, mac in enumerate(mac_index):
        if i >= 5:
            break
        print(f"  {mac}")

    result_hosts: List[Dict[str, Any]] = []

    for host in esxi_hosts:
        host_entry = {
            "name": host.get("name", host.get("ip")),
            "ip": host.get("ip"),
            "vmnics": [],
        }
        # DEBUG: نمایش چند MAC اول ESXi
        print(f"\n🔎 ESXi host {host_entry['name']} MACs (first 3):")
        for i, vmnic in enumerate(host.get("vmnics", [])):
            if i >= 3:
                break
            print(f"  {vmnic['mac']}")

        for vmnic in host.get("vmnics", []):
            mac = vmnic.get("mac")
            if not mac:
                continue
            links = mac_index.get(mac, [])
            if not links:
                # DEBUG: چاپ MACهای بدون انطباق
                print(f"⚠ No switch match for ESXi MAC: {mac}")
            host_entry["vmnics"].append(
                {
                    "if_index": vmnic.get("if_index", ""),
                    "if_name": vmnic.get("if_name", ""),
                    "mac": mac,
                    "links": links,
                }
            )
        result_hosts.append(host_entry)

    return {"hosts": result_hosts}


def print_table(correlation: Dict[str, Any]) -> None:
    hosts = correlation.get("hosts", [])
    if not hosts:
        print("\n⚠ No ESXi host data received. Output is empty.")
        return

    has_any_vmnic = False
    for host in hosts:
        if host.get("vmnics"):
            has_any_vmnic = True
            break

    if not has_any_vmnic:
        print("\n⚠ No VMNIC (MAC addresses) found on hosts. Output is empty.")
        return

    header = f"{'Host':<12} {'vmnic':<8} {'MAC':<20} {'Switch':<10} {'VLAN':<6} {'Port':<20}"
    print("\n" + header)
    print("-" * len(header))

    for host in hosts:
        host_name = host["name"]
        for vmnic in host["vmnics"]:
            vmnic_name = vmnic["if_name"]
            mac = vmnic["mac"]
            links = vmnic.get("links", [])
            if not links:
                print(f"{host_name:<12} {vmnic_name:<8} {mac:<20} {'-':<10} {'-':<6} {'-':<20}")
            else:
                for link in links:
                    sw_name = link["switch_name"]
                    vlan = link["vlan"]
                    port_name = link["port_if_name"]
                    print(
                        f"{host_name:<12} {vmnic_name:<8} {mac:<20} {sw_name:<10} {str(vlan):<6} {port_name:<20}"
                    )


def discovery_full(config: Dict[str, Any]) -> None:
    esxi_cfgs = config.get("esxi_hosts", [])
    sw_cfgs = config.get("switches", [])
    out_cfg = config.get("output", {})
    out_json = out_cfg.get("json_file", "correlation_output.json")

    if not esxi_cfgs:
        print("❌ No ESXi hosts defined in config.json.")
        return
    if not sw_cfgs:
        print("❌ No switches defined in config.json.")
        return

    esxi_hosts: List[Dict[str, Any]] = []
    switches: List[Dict[str, Any]] = []

    print(f"🔍 Starting discovery for {len(esxi_cfgs)} ESXi host(s)...")
    for hcfg in esxi_cfgs:
        ip = hcfg.get("ip", "")
        community = hcfg.get("community", "public")
        hostname_oid = hcfg.get("hostname_oid")
        mac_table_oid = hcfg.get("mac_table_oid")
        print(f"  → Querying {ip} ...")
        esxi = discover_esxi_host(ip, community, mac_table_oid, hostname_oid)
        vmnics = []
        for mac, if_name in esxi.mac_table.items():
            vmnics.append({"mac": mac, "if_name": if_name, "if_index": ""})
        print(f"    Found {len(vmnics)} MAC address(es) on this host.")
        esxi_hosts.append({
            "ip": esxi.ip,
            "name": esxi.name or esxi.ip,
            "vmnics": vmnics,
        })

    print(f"\n🔍 Starting discovery for {len(sw_cfgs)} switch(es)...")
    for idx, scfg in enumerate(sw_cfgs):
        ip = scfg.get("ip", "")
        community = scfg.get("community") or scfg.get("base_community") or "public"
        print(f"  → Querying switch {ip} ...")
        sw = discover_switch(ip, community)
        print(f"    Found {len(sw.get('fdb', []))} MAC address(es) in FDB.")
        switches.append(sw)

        if "vlans" not in config["switches"][idx]:
            vlans = discover_switch_vlans(ip, community)
            config["switches"][idx]["vlans"] = vlans

    save_config(config)

    db.save_esxi_hosts(esxi_hosts)
    db.save_switches(switches)

    corr = correlate(esxi_hosts, switches)
    db.save_correlation(corr)

    print_table(corr)

    out_path = os.path.join(get_script_dir(), out_json)
    with open(out_path, "w") as f:
        json.dump(corr, f, indent=2)
    print(f"\n📁 Correlation result saved to {out_json}")


def refresh_switch_vlans(config: Dict[str, Any]) -> None:
    sw_cfgs = config.get("switches", [])
    if not sw_cfgs:
        print("No switches defined in config.")
        return

    for idx, scfg in enumerate(sw_cfgs):
        community = scfg.get("community") or scfg.get("base_community") or "public"
        print(f"[INFO] VLAN discovery for switch: {scfg['name']} ({scfg['ip']}) ...")
        vlans = discover_switch_vlans(scfg.get("ip", ""), community)
        config["switches"][idx]["vlans"] = vlans
        print(f"  VLANs: {vlans}")

    save_config(config)
    print("\n[OK] Switch VLANs updated in config.json.")


def main() -> None:
    config = load_config()

    print("SNMP ESXi <-> Switch Link Discovery")
    print("1) Full discovery (ESXi + Switch + VLAN auto-discovery if needed)")
    print("2) Scan and update switch VLANs only (config.json)")
    choice = input("Enter your choice (1/2): ").strip()

    if choice == "2":
        refresh_switch_vlans(config)
    else:
        discovery_full(config)


if __name__ == "__main__":
    main()