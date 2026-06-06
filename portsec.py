import re
from flask import Blueprint, request, flash, redirect, url_for
from models import db, Switch, PortSecLog, CredentialProfile
from connection import get_connection
from app_logging import log_event  # فقط برای لاگ DB

portsec_bp = Blueprint('portsec', __name__)

def parse_security_limit(output):
    max_match = re.search(r'Max Addresses\s+:\s+(\d+)', output)
    curr_match = re.search(r'Current Addresses\s+:\s+(\d+)', output)
    if max_match and curr_match:
        return int(max_match.group(1)), int(curr_match.group(1))
    return 0, 0

@portsec_bp.route("/remove-mac", methods=["POST"])
def remove_mac():
    mac_input = request.form.get("mac", "").strip()
    port = request.form.get("port", "").strip()
    switch_id = request.form.get("switch_id", "").strip()

    if not mac_input or not port or not switch_id:
        flash("Missing required fields (mac/port/switch_id).", "danger")
        return redirect(url_for("macsec.search_mac", mac=mac_input))

    # ۱) پاکسازی کامل MAC (حذف هرگونه کاراکتر غیرهگز)
    clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac_input)
    if len(clean_mac) != 12:
        flash(f"Invalid MAC format: {mac_input}. Must be 12 hex characters.", "danger")
        return redirect(url_for("macsec.search_mac", mac=mac_input))

    # ۲) فرمت‌دهی استاندارد سیسکو: xxxx.xxxx.xxxx
    formatted_mac = f"{clean_mac[0:4]}.{clean_mac[4:8]}.{clean_mac[8:12]}".lower()

    sw = Switch.query.get_or_404(int(switch_id))
    profile = CredentialProfile.query.get(sw.profile_id)

    if not profile:
        flash("Credential profile not found!", "danger")
        return redirect(url_for("macsec.search_mac", mac=mac_input))

    switch_dict = {
        "device_type": sw.device_type or "cisco_ios",
        "host": sw.ip,
        "username": profile.username,
        "password": profile.get_password(),
    }
    secret = profile.get_secret()
    if secret:
        switch_dict["secret"] = secret

    conn = None
    try:
        conn = get_connection(switch_dict)
        if not conn:
            raise RuntimeError("Connection could not be established")

        if secret:
            conn.enable()

        # ۳) ارسال دستور (داخل send_config_set نیازی به 'configure terminal' و 'end' نیست)
        cmd_to_run = f"no switchport port-security mac-address sticky {formatted_mac}"
        commands = [
            f"interface {port}",
            cmd_to_run,
        ]

        # قبلاً print بود -> فقط لاگ DB
        try:
            log_event(
                level="INFO",
                message=f"[PORTSEC] sending commands ip={sw.ip} port={port} mac={formatted_mac} commands={commands}",
                switch=sw,
                status="success",
                file_path="portsec.py",
            )
        except Exception:
            pass

        output = conn.send_config_set(commands)

        # اگر سوئیچ خطا بدهد، همانجا fail کن تا مجبور نشی دوبار کلیک کنی
        err_markers = [
            "% Invalid input",
            "% Incomplete command",
            "% Ambiguous command",
            "% Error",
            "Invalid input detected",
        ]
        if any(m in (output or "") for m in err_markers):
            raise RuntimeError(output)

        # ذخیره کانفیگ صحیح در IOS (بهتر از write memory با send_command)
        try:
            conn.save_config()
        except Exception:
            # fallback
            conn.send_command("write memory")

        # ۴) لاگ در دیتابیس
        new_log = PortSecLog(
            switch_id=sw.id,
            mac=clean_mac.lower(),
            port=port,
            action="REMOVE_STICKY",
        )
        db.session.add(new_log)
        db.session.commit()

        # لاگ موفقیت برای logs.html
        try:
            log_event(
                level="INFO",
                message=f"[PORTSEC] removed sticky mac={formatted_mac} port={port} ip={sw.ip}",
                switch=sw,
                status="success",
                file_path="portsec.py",
            )
        except Exception:
            pass

        flash(f"MAC {formatted_mac} removed successfully from {port}", "success")

    except Exception as e:
        # لاگ خطا برای logs.html
        try:
            log_event(
                level="ERROR",
                message=f"[PORTSEC] failed remove sticky mac={formatted_mac} port={port} ip={sw.ip} err={e}",
                switch=sw if 'sw' in locals() else None,
                status="failed",
                file_path="portsec.py",
            )
        except Exception:
            pass

        flash(f"Error executing command: {str(e)}", "danger")

    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass

    return redirect(url_for("macsec.search_mac", mac=mac_input))
