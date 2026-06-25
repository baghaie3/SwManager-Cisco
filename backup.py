import os

from datetime import datetime
from pathlib import Path
import threading
from smb.SMBConnection import SMBConnection
from flask import (
    Blueprint,
    send_file,
    abort,
    render_template,
    current_app,
    request,
    redirect,
    url_for,
    flash,
)
from connection import get_connection
from models import db, Switch, CredentialProfile, Log, ScheduledJob, Backup, SMBTransfer
from steganography import encode_backup_to_images, decode_backup_from_images, STEGO_DIR
backup_bp = Blueprint("backup", __name__)
def log_event(
    switch: Switch | None,
    level: str,
    status: str,
    message: str,
    file_path: str | None = None,
) -> None:
    log = Log(
        switch_id   = switch.id   if switch else None,
        switch_name = switch.name if switch else None,
        level       = level,
        status      = status,
        message     = message,
        file_path   = file_path,
    )
    db.session.add(log)
    db.session.commit()
def get_switch_and_profile(switch_id: int) -> tuple[Switch, CredentialProfile]:
    sw = Switch.query.get(switch_id)
    if not sw:
        raise ValueError(f"Switch id={switch_id} not found")
    if not sw.profile_id:
        raise ValueError(f"Switch '{sw.name}' has no credential profile")
    profile = CredentialProfile.query.get(sw.profile_id)
    if not profile:
        raise ValueError(f"CredentialProfile id={sw.profile_id} not found")
    return sw, profile
def build_netmiko_params(sw: Switch, profile: CredentialProfile) -> dict:
    params = {
        "device_type": sw.device_type or "cisco_ios",
        "host":        sw.ip,
        "username":    profile.username,
        "password":    profile.get_password(),
    }
    secret = profile.get_secret()
    if secret:
        params["secret"] = secret
    return params
def backup_running_config(switch_id: int) -> dict:
    from app import app  # circular import guard
    with app.app_context():
        # ── ۱. lookup ──────────────────────────────────────────
        try:
            sw, profile = get_switch_and_profile(switch_id)
        except Exception as e:
            log_event(None, "error", "failed", f"[lookup] {e}")
            return {"success": False, "error": str(e), "output": None}
        # ── ۲. connect & fetch ─────────────────────────────────
        try:
            params = build_netmiko_params(sw, profile)
            conn = get_connection(params)
            
            if conn:
                with conn:
                    if params.get("secret"):
                        conn.enable()
                    output = conn.send_command("show running-config")
            else:
                error_msg = f"Backup failed for {params['host']}: Connection Error"
                log_event(sw, "error", "failed", f"[connect] {error_msg}")
                return {"success": False, "error": error_msg, "output": None}      
        except Exception as e:
            log_event(sw, "error", "failed", f"[connect] {e}")
            return {"success": False, "error": str(e), "output": None}
        # ── ۳. steganography encode ────────────────────────────
        backup_id = None
        try:
            timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_id = encode_backup_to_images(
                config_text = output,
                switch_name = sw.name,
                switch_ip   = sw.ip,
                timestamp   = timestamp,
                switch_id   = sw.id,
            )
            log_event(
                sw,
                "info",
                "success",
                f"[backup] New backup created with ID={backup_id}",
                file_path=backup_id,
            )
            # update last_run of scheduled job
            job = ScheduledJob.query.filter_by(switch_id=sw.id).first()
            if job:
                job.last_run = datetime.now()
                db.session.commit()

            return {
                "success":   True,
                "error":     None,
                "output":    output,
                "backup_id": backup_id,
            }
        except Exception as e:
            log_event(
                sw,
                "error",
                "failed",
                f"[stego] {e}",
                file_path=backup_id,
            )
            return {
                "success":   False,
                "error":     str(e),
                "output":    output,
                "backup_id": backup_id,
            }
@backup_bp.route("/backup/run/<int:switch_id>", methods=["POST"])
def run_backup(switch_id: int):
    result = backup_running_config(switch_id)
    if not result["success"]:
        flash(f"Backup failed: {result['error']}", "danger")
    else:
        flash("Backup completed successfully.", "success")
    return redirect(url_for("list_switches"))
@backup_bp.route("/backup/list/<int:switch_id>")
def list_backups(switch_id: int):

    from models import Backup, SMBTransfer

    sw = Switch.query.get_or_404(switch_id)

    backup_records = (
        Backup.query
        .filter_by(switch_id=switch_id)
        .order_by(Backup.created_at.desc())
        .all()
    )

    backups = []

    for b in backup_records:

        sent = SMBTransfer.query.filter_by(
            backup_id=b.backup_id,
            status="success"
        ).first()

        backups.append({
            "time": b.created_at,
            "backup_id": b.backup_id,
            "smb_status": "success" if sent else "pending"
        })

    return render_template(
        "backups.html",
        switch=sw,
        backups=backups
    )
@backup_bp.route("/backup/download")
def download_backup():
    backup_id = request.args.get("backup_id", "").strip()
    if not backup_id:
        flash("Missing backup_id.", "danger")
        return redirect(url_for("list_switches"))
    if len(backup_id) != 32 or not backup_id.isalnum():
        flash("Invalid backup_id.", "danger")
        return redirect(url_for("list_switches"))
    try:
        config_text = decode_backup_from_images(backup_id)
    except FileNotFoundError:
        flash("Backup not found.", "danger")
        return redirect(url_for("list_switches"))
    except Exception as e:
        flash(f"Failed to decode: {e}", "danger")
        return redirect(url_for("list_switches"))
    from io import BytesIO
    mem_file = BytesIO()
    mem_file.write(config_text.encode("utf-8"))
    mem_file.seek(0)
    filename = f"running-config-{backup_id[:8]}.txt"
    return send_file(
        mem_file,
        as_attachment=True,
        download_name=filename,
        mimetype="text/plain",
    )
@backup_bp.route("/backup/download_stego")
def download_stego_backup():
    return download_backup()
progress_status = {"current": 0, "total": 0, "is_running": False}
def run_backups_in_background(job_ids):
    global progress_status
    progress_status["is_running"] = True
    progress_status["total"] = len(job_ids)
    progress_status["current"] = 0
    from models import db
    from app import app
    import time
    with app.app_context():
        for job_id in job_ids:
            try:
                # اجرای بکاپ (خود این تابع لاگ می‌زند)
                backup_running_config(job_id)
            except Exception as e:
                print(f"Error in background job {job_id}: {e}")        
            progress_status["current"] += 1
            time.sleep(3) # فاصله ۵ ثانیه‌ای طبق درخواست شما         
    progress_status["is_running"] = False
@backup_bp.route("/runalljob", methods=["POST"])
def run_all_jobs():
    from models import ScheduledJob
    if progress_status["is_running"]:
        return {"status": "already_running"}, 400
    jobs = ScheduledJob.query.all()
    job_ids = [j.switch_id for j in jobs]   
    if not job_ids:
        return {"status": "no_jobs"}, 404
    thread = threading.Thread(target=run_backups_in_background, args=(job_ids,))
    thread.start()
    return {"status": "started", "total": len(job_ids)}, 200
@backup_bp.route("/runall-status")
def run_all_status():
    return progress_status


