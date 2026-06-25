from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from models import db, Switch, MacAddressLog, CredentialProfile
from connection import get_connection
import re
from sqlalchemy import desc 
import pytz
import traceback
from app_logging import log_event
macsec_bp = Blueprint("macsec", __name__)
def _macscan_log(level: str, msg: str):
    try:
        logger = current_app.logger
        fn = getattr(logger, level, logger.info)
        fn(f"[MACSCAN] {msg}")
    except Exception:
        try:
            log_event(
                level="ERROR",
                message=f"[MACSCAN] logger failed; original=({level}) {msg}",
                switch=None,
                status="failed",
                file_path="macsearch.py",
                event_type="mac_scan_manual",
            )
        except Exception:
            pass

    try:
        lvl = (level or "").lower()
        db_level = "INFO"
        db_status = "success"
        if lvl in ("warning", "warn"):
            db_level = "WARNING"
            db_status = "failed"
        elif lvl in ("error", "exception", "critical"):
            db_level = "ERROR"
            db_status = "failed"

        log_event(
            level=db_level,
            message=f"[MACSCAN] {msg}",
            switch=None,
            status=db_status,
            file_path="macsearch.py",
            event_type="MACScanManual",
        )
    except Exception:
        pass   
def build_netmiko_params(sw: Switch, profile: CredentialProfile) -> dict:
    params = {
        "device_type": sw.device_type or "cisco_ios",
        "host": sw.ip,
        "username": profile.username,
        "password": profile.get_password(),
    }
    secret = profile.get_secret()
    if secret:
        params["secret"] = secret
    return params
def build_device_info(switch: Switch) -> dict:
    profile = CredentialProfile.query.get(switch.profile_id)
    if not profile:
        raise ValueError(f"No credential profile for switch {switch.name}")
    return build_netmiko_params(switch, profile)

def fetch_mac_table(switch: Switch):
    device_info = build_device_info(switch)
    conn = get_connection(device_info)
    if not conn:
        try:
            log_event(
                level="ERROR",
                message=f"[MACSCAN] Connection failed to {switch.ip}",
                switch=switch,
                status="failed",
                file_path="macsearch.py",
                event_type="MACScanManual",
            )
        except Exception:
            pass
        return ""

    try:
        if device_info.get("secret"):
            conn.enable()
        output = conn.send_command("show port-security address")
    except Exception as e:
        try:
            log_event(
                level="ERROR",
                message=f"[MACSCAN] ERROR fetching port-security table from {switch.ip}: {e}",
                switch=switch,
                status="failed",
                file_path="macsearch.py",
                event_type="MACScanManual",
            )
        except Exception:
            pass
        output = ""
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

    return output

def parse_mac_table(output: str, switch_id: int):
    mac_entries = []
    pattern = re.compile(
        r'^\s*(\d+)\s+'
        r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'
        r'(\S+)\s+'
        r'(\S+)'
    )
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        match = pattern.match(line)
        if not match:
            continue
        vlan, mac, _type, port = match.groups()
        mac_entries.append({
            "switch_id": switch_id,
            "mac": re.sub(r'[^0-9a-fA-F]', '', mac).lower(),
            "vlan": vlan,
            "port": port,
        })
    return mac_entries
def store_mac_entries(entries):
    now = datetime.utcnow()
    for e in entries:
        last_record = MacAddressLog.query.filter_by(
            switch_id=e["switch_id"], mac=e["mac"], vlan=e["vlan"]
        ).order_by(MacAddressLog.last_seen.desc()).first()
        if last_record and last_record.port == e["port"]:
            last_record.last_seen = now
        else:
            db.session.add(MacAddressLog(
                switch_id=e["switch_id"], mac=e["mac"], vlan=e["vlan"],
                port=e["port"], first_seen=now, last_seen=now
            ))
    db.session.commit()
def scan_switch(app, switch_id: int):
    with app.app_context():
        try:
            app.logger.info(f"[MACSCAN] start switch_id={switch_id}")
            try:
                log_event(
                    level="INFO",
                    message=f"[MACSCAN] start switch_id={switch_id}",
                    switch=None,
                    status="success",
                    file_path="macsearch.py",
                    event_type="MACScanManual",
                )
            except Exception:
                pass

            switch = Switch.query.get(switch_id)
            if not switch:
                app.logger.warning(f"[MACSCAN] switch not found switch_id={switch_id}")
                try:
                    log_event(
                        level="WARNING",
                        message=f"[MACSCAN] switch not found switch_id={switch_id}",
                        switch=None,
                        status="failed",
                        file_path="macsearch.py",
                        event_type="MACScanManual",
                    )
                except Exception:
                    pass
                return

            output = fetch_mac_table(switch)
            if not output or "not enabled" in output.lower():
                app.logger.warning(
                    f"[MACSCAN] empty/disabled output ip={switch.ip} switch_id={switch_id}"
                )
                try:
                    log_event(
                        level="WARNING",
                        message=f"[MACSCAN] empty/disabled output ip={switch.ip} switch_id={switch_id}",
                        switch=switch,
                        status="failed",
                        file_path="macsearch.py",
                        event_type="MACScanManual",
                    )
                except Exception:
                    pass
                return

            app.logger.debug(
                f"[MACSCAN] output head ip={switch.ip}: {output[:250]!r}"
            )

            entries = parse_mac_table(output, switch.id)
            app.logger.info(
                f"[MACSCAN] parsed entries={len(entries)} ip={switch.ip}"
            )
            try:
                log_event(
                    level="INFO",
                    message=f"[MACSCAN] parsed entries={len(entries)} ip={switch.ip}",
                    switch=switch,
                    status="success",
                    file_path="macsearch.py",
                    event_type="MACScanManual",
                )
            except Exception:
                pass

            if not entries:
                return

            store_mac_entries(entries)

            app.logger.info(
                f"[MACSCAN] done switch_id={switch_id} entries={len(entries)}"
            )
            try:
                log_event(
                    level="INFO",
                    message=f"[MACSCAN] done switch_id={switch_id} entries={len(entries)}",
                    switch=switch,
                    status="success",
                    file_path="macsearch.py",
                    event_type="MACScanManual",
                )
            except Exception:
                pass

        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass

            app.logger.error(
                f"[MACSCAN] failed switch_id={switch_id} err={e}"
            )
            app.logger.error(traceback.format_exc())
            try:
                log_event(
                    level="ERROR",
                    message=f"[MACSCAN] failed switch_id={switch_id} err={e}",
                    switch=None,
                    status="failed",
                    file_path="macsearch.py",
                    event_type="MACScanManual",
                )
            except Exception:
                pass
@macsec_bp.route("/mac-search", methods=["GET", "POST"])
def search_mac():
    raw_mac = request.args.get("mac", "").strip()
    results = []
    tehran_tz = pytz.timezone("Asia/Tehran")

    if raw_mac:
        norm = re.sub(r"[^0-9a-fA-F]", "", raw_mac)

        results = (
            MacAddressLog.query.filter(
                MacAddressLog.mac.contains(norm.lower())
            )
            .order_by(db.desc(MacAddressLog.last_seen))
            .all()
        )

        # لاگ خودِ سرچ MAC
        try:
            log_event(
                level="INFO",
                message=(
                    f"[MACSEARCH] search_mac raw_mac={raw_mac} "
                    f"normalized={norm.lower()} results_count={len(results)}"
                ),
                switch=None,
                status="success",
                file_path="macsearch.py",
                event_type="MACSearchUser",
            )
        except Exception:
            pass

    for row in results:
        if row.last_seen:
            if row.last_seen.tzinfo is None:
                utc_dt = row.last_seen.replace(tzinfo=pytz.utc)
            else:
                utc_dt = row.last_seen
            row.last_seen_display = utc_dt.astimezone(tehran_tz).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        else:
            row.last_seen_display = "N/A"

    switches = Switch.query.all()
    return render_template(
        "mac_search.html", results=results, mac=raw_mac, switches=switches
    )
@macsec_bp.route("/mac-search/scan/<int:switch_id>", methods=["POST"])
def manual_scan(switch_id):
    app = current_app._get_current_object()

    # لاگ تریگر شدن اسکن دستی
    try:
        log_event(
            level="INFO",
            message=f"[MACSCAN] manual_scan triggered from UI switch_id={switch_id}",
            switch=None,
            status="started",
            file_path="macsearch.py",
            event_type="MACScanmanual",
        )
    except Exception:
        pass

    # اجرای اسکن روی سوییچ
    # اگر می‌خوای اسکن در پس‌زمینه (non-blocking) اجرا شود:
    import threading
    threading.Thread(
        target=scan_switch,
        args=(app, switch_id),
        daemon=True,
    ).start()

    # پیام به کاربر
    flash("Manual MAC scan started for the selected switch.", "info")

    # حتماً یک response معتبر برگردان
    return redirect(url_for("macsec.search_mac"))
