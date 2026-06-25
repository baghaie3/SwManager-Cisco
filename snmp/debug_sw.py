from snmp_sw import discover_switch
from snmp_main import load_config

cfg = load_config()
sw_cfgs = cfg.get("switches", [])
if not sw_cfgs:
    print("no switches in config")
else:
    sw = sw_cfgs[0]
    result = discover_switch(sw["ip"], sw["base_community"])
    print(f"Switch: {result['ip']}")
    print(f"FDB entries: {len(result['fdb'])}")
    for entry in result['fdb'][:10]:
        print(f"  MAC: {entry['mac']}, Port: {entry['if_name']}, VLAN: {entry['vlan']}")