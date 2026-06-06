from flask import Blueprint, request, jsonify, render_template
import networkx as nx
from connection import get_connection
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from models import db, Switch
from auth_required import login_required

topology_bp = Blueprint('topology', __name__, url_prefix='/topology')

# متغیر سراسری برای پیشرفت کار (جهت سیستم تک کاربره)
progress = {"current": 0, "total": 0, "percent": 0}

def normalize_interface(name: str) -> str:
    if not name:
        return ""
    n = name.strip().lower()

    patterns = [
        (r"^gigabitethernet", "GE"),
        (r"^gigabite", "GE"),
        (r"^gige", "GE"),
        (r"^gi", "GE"),

        (r"^tengigabitethernet", "TE"),
        (r"^tengigabite", "TE"),
        (r"^tengige", "TE"),
        (r"^te", "TE"),

        (r"^fastethernet", "FE"),
        (r"^fa", "FE"),

        (r"^ethernet", "E"),
        (r"^et", "E"),

        (r"^port-channel", "PO"),
        (r"^portchannel", "PO"),
        (r"^po", "PO"),

        (r"^loopback", "LO"),
        (r"^lo", "LO"),

        (r"^vlan", "VLAN"),

        (r"^serial", "SE"),
        (r"^se", "SE"),
    ]

    for pattern, short in patterns:
        m = re.match(pattern, n)
        if m:
            num = n[m.end():]
            return f"{short}{num}".upper()

    return name.upper()

def resolve_device(remote_ip, remote_name):
    # اگر IP وجود ندارد، کاملاً نادیده گرفته شود
    if not remote_ip:
        return None, None

    # شناسه و لیبل هر دو فقط IP باشند
    return remote_ip, remote_ip

@topology_bp.route('/')
@login_required
def index():
    return render_template('topology.html')

@topology_bp.route('/devices', methods=['GET'])
@login_required
def get_devices():
    # خواندن سوئیچ‌ها مستقیماً از دیتابیس پروژه اصلی
    switches = Switch.query.all()
    data = [{"name": sw.name, "ip": sw.ip} for sw in switches]
    return jsonify(data)

def scan_device(dev_info, protocol="both"):
    """
    اتصال به سوئیچ با استفاده از اطلاعات استخراج شده (دیکشنری ساده)
    """
    try:
        dev = {
            "device_type": dev_info["device_type"],
            "host": dev_info["ip"],
            "username": dev_info["username"],
            "password": dev_info["password"],
            "timeout": 5,
            "conn_timeout": 5
        }

        conn = get_connection(dev)
        if not conn:
            print(f"Skipping {dev['host']} due to connection failure.")
            
        out = ""
        out_lldp = ""
        
        if protocol in ["cdp", "both"]:
            try:
                out = conn.send_command("show cdp neighbors detail")
            except:
                out = ""
        if protocol in ["lldp", "both"]:
            try:
                out_lldp = conn.send_command("show lldp neighbors detail")
            except:
                out_lldp = ""
        conn.disconnect()

        # ---------- بخش پارس کردن CDP ----------
        neighbors = []
        if out:
            blocks = re.split(r'-{5,}', out)
            for blk in blocks:
                if "Device ID" not in blk: continue
                host   = re.search(r"Device ID:\s*(.+)", blk)
                local  = re.search(r"Interface:\s*(\S+),", blk)
                remote = re.search(r"Port ID \(outgoing port\):\s*(\S+)", blk)
                ipaddr = re.search(r"IP address:\s*([\d\.]+)", blk)

                def short_port(p):
                    if not p: return ""
                    return p.replace("Ethernet","E").replace("FastEthernet","FE").replace("GigabitEthernet","GE")

                neighbors.append({
                    "local_int": normalize_interface(local.group(1)) if local else "",
                    "remote_int": normalize_interface(remote.group(1)) if remote else "",
                    "remote_ip": ipaddr.group(1) if ipaddr else "",
                    "remote_name": host.group(1).strip() if host else "",
                    "protocol": "CDP"
                })
        
        # (بخش مربوط به پارس LLDP را اگر دارید در اینجا قرار دهید)
        
        return {"ip": dev_info["ip"], "name": dev_info["name"], "neighbors": neighbors}

    except Exception as e:
        print(f"Connection error on {dev_info['ip']}: {e}")
        return None

@topology_bp.route('/scan', methods=['POST'])
@login_required
def scan():
    global progress
    data = request.json
    ips = data.get("devices", [])
    protocol = data.get("protocol", "both")

    if not ips:
        return jsonify({"nodes": [], "edges": []})

    # ۱. واکشی آبجکت‌ها از دیتابیس
    switches_to_scan = Switch.query.filter(Switch.ip.in_(ips)).all()
    
    # ۲. استخراج داده‌های لازم به صورت دیکشنری 
    devices_data = []
    for sw in switches_to_scan:
        if sw.profile:  # مطمئن شوید که پروفایل (یوزر/پسورد) به سوئیچ اختصاص داده شده است
            devices_data.append({
                "ip": sw.ip,
                "name": sw.name,
                "device_type": sw.device_type or "cisco_ios",
                "username": sw.profile.username,
                "password": sw.profile.get_password()
            })

    progress["total"] = len(devices_data)
    progress["current"] = 0
    progress["percent"] = 0

    results = []
    # ۳. ارسال اطلاعات به ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_device, dev_info, protocol): dev_info for dev_info in devices_data}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
            progress["current"] += 1
            if progress["total"] > 0:
                progress["percent"] = int((progress["current"] / progress["total"]) * 100)

    # ۴. ساخت گراف با استفاده از NetworkX
    G = nx.Graph()

    for dev in results:
        node_id = dev["ip"]
        if not G.has_node(node_id):
            G.add_node(node_id, label=node_id)

        for n in dev.get("neighbors", []):
            # توجه: تابع resolve_device باید در این فایل در دسترس باشد
            remote_id, remote_label = resolve_device(
                n.get("remote_ip", ""),
                n.get("remote_name", "")
            )

            if not remote_id:
                continue

            if not G.has_node(remote_id):
                G.add_node(remote_id, label=remote_label)

            proto = n.get("protocol", "CDP")
            G.add_edge(
                node_id,
                remote_id,
                local=n.get("local_int", ""),
                remote_port=n.get("remote_int", ""),
                protocol=proto
            )

    # ۵. تبدیل گراف به فرمت JSON برای Frontend
    nodes = []
    for n in G.nodes():
        nodes.append({
            "id": str(n),
            "label": str(G.nodes[n].get("label", n))
        })

    edges = []
    for u, v, d in G.edges(data=True):
        label = ""
        if d.get("local") or d.get("remote_port"):
            label = f"{d.get('local', '')} → {d.get('remote_port', '')}"

        proto = d.get("protocol", "CDP")
        if proto == "CDP":
            color = "#3498db"
        elif proto == "LLDP":
            color = "#e67e22"
        else:
            color = "#2ecc71"

        edges.append({
            "from": str(u),
            "to": str(v),
            "label": label,
            "color": {
                "color": color,
                "highlight": color,
                "hover": color
            },
            "width": 3 if proto == "BOTH" else 2
        })

    # ارسال دیتای واقعی به جاوااسکریپت
    return jsonify({"nodes": nodes, "edges": edges})

@topology_bp.route('/progress', methods=['GET'])
@login_required
def get_progress():
    return jsonify(progress)
