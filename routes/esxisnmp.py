from flask import Blueprint, jsonify, request
from flask_login import login_required

from models import EsxiHost, EsxiCredentialProfile, EsxiLink, db
from security import decrypt  # اگر لازم شد در scan_esxi_topology استفاده شود

esxisnmp_bp = Blueprint("esxisnmp", __name__, url_prefix="/esxi-snmp")


def _serialize_esxi_link(link: EsxiLink) -> dict:
    return {
        "id": link.id,
        "esxi_host_id": link.esxi_host_id,
        "esxi_if_name": link.esxi_if_name,
        "esxi_if_index": link.esxi_if_index,
        "neighbor_device": link.neighbor_device,
        "neighbor_port": link.neighbor_port,
        "neighbor_ip": link.neighbor_ip,
        "last_seen": link.last_seen.isoformat() if link.last_seen else None,
    }


def scan_esxi_topology(ip: str, community: str) -> dict:
    """
    Placeholder SNMP discovery implementation.
    بعداً با منطق واقعی SNMP جایگزین می‌کنی.
    خروجی باید ساختار زیر را برگرداند:
    {
        "nodes": [...],
        "links": [
            {
                "esxi_if_name": "...",
                "esxi_if_index": 1,
                "neighbor_device": "...",
                "neighbor_port": "...",
                "neighbor_ip": "..."
            },
            ...
        ]
    }
    """
    return {"nodes": [], "links": []}


@esxisnmp_bp.route("/host/<int:host_id>/scan", methods=["POST"])
@login_required
def scan_host_topology(host_id: int):
    host: EsxiHost | None = EsxiHost.query.get(host_id)
    if host is None:
        return jsonify({"error": "ESXi host not found"}), 404

    if not host.credential_profile:
        return jsonify({"error": "No credential profile is associated with this host"}), 400

    cred: EsxiCredentialProfile = host.credential_profile
    community = cred.get_snmp_community()
    if not community:
        return jsonify({"error": "SNMP community is empty in the credential profile"}), 400

    ip = host.ip_address

    payload = request.get_json(silent=True) or {}
    save_links = bool(payload.get("save_links", True))

    try:
        topology = scan_esxi_topology(ip=ip, community=community)
    except Exception as exc:
        return jsonify({"error": f"SNMP scan failed: {exc}"}), 500

    nodes = topology.get("nodes", [])
    links = topology.get("links", [])

    if save_links and links:
        _persist_links(host, links)

    return jsonify({"nodes": nodes, "links": links})


def _persist_links(host: EsxiHost, links: list[dict]) -> None:
    EsxiLink.query.filter_by(esxi_host_id=host.id).delete()

    for l in links:
        link = EsxiLink(
            esxi_host_id=host.id,
            esxi_if_name=l.get("esxi_if_name") or l.get("if_name") or "",
            esxi_if_index=l.get("esxi_if_index"),
            neighbor_device=l.get("neighbor_device"),
            neighbor_port=l.get("neighbor_port"),
            neighbor_ip=l.get("neighbor_ip"),
        )
        db.session.add(link)

    db.session.commit()


@esxisnmp_bp.route("/host/<int:host_id>/links", methods=["GET"])
@login_required
def get_host_links(host_id: int):
    host: EsxiHost | None = EsxiHost.query.get(host_id)
    if host is None:
        return jsonify({"error": "ESXi host not found"}), 404

    links = [_serialize_esxi_link(l) for l in host.links]
    return jsonify({"links": links})