import os
import socket
import tempfile
import zipfile
import uuid
import pytz
from datetime import datetime, timedelta
from pathlib import Path

from flask import (
    Blueprint,
    flash,
    redirect,
    request,
    url_for,
    render_template,
    session
)

from smb.SMBConnection import SMBConnection

from models import (
    db,
    Backup,
    SMBTransfer,
    Log,
)

from steganography import STEGO_DIR


smb_bp = Blueprint("smb", __name__)

SMB_SESSION_KEY = "smb_credentials"
SMB_SESSION_TTL_MINUTES = 30


def _set_smb_session(username, password, server, share, domain):
    expires_at = datetime.utcnow() + timedelta(minutes=SMB_SESSION_TTL_MINUTES)
    session[SMB_SESSION_KEY] = {
        "username": username,
        "password": password,
        "server": server,
        "share": share,
        "domain": domain or "",
        "expires_at": expires_at.isoformat(),
    }


def _get_smb_session():
    data = session.get(SMB_SESSION_KEY)
    if not data:
        return None

    try:
        expires_at = datetime.fromisoformat(data["expires_at"])
    except Exception:
        session.pop(SMB_SESSION_KEY, None)
        return None

    if datetime.utcnow() > expires_at:
        session.pop(SMB_SESSION_KEY, None)
        return None

    return data


def create_smb_connection():
    cfg = _get_smb_session()

    if not cfg:
        username = os.getenv("SMB_USER")
        password = os.getenv("SMB_PASS")
        server = os.getenv("SMB_SERVER")
        domain = os.getenv("SMB_DOMAIN") or ""

        if not username or not password or not server:
            raise Exception("SMB credentials not set (session expired or env missing).")
    else:
        username = cfg["username"]
        password = cfg["password"]
        server = cfg["server"]
        domain = cfg.get("domain") or ""

    conn = SMBConnection(
        username=username,
        password=password,
        my_name=socket.gethostname(),
        remote_name=server,
        domain=domain,
        use_ntlm_v2=True,
        is_direct_tcp=True,
    )

    connected = conn.connect(
        server,
        445,
        timeout=30,
    )

    if not connected:
        raise Exception("SMB connection failed")

    return conn


def smb_log(
    switch_id,
    switch_name,
    level,
    status,
    message,
    file_path=None
):

    log = Log(
        switch_id=switch_id,
        switch_name=switch_name,
        level=level,
        status=status,
        message=message,
        file_path=file_path
    )

    db.session.add(log)
    db.session.commit()


def create_backup_zip(
    backup_folder: Path,
    backup_id: str
):

    temp_dir = tempfile.gettempdir()

    unique_name = (
        f"{backup_id}_{uuid.uuid4().hex}.zip"
    )

    zip_path = os.path.join(
        temp_dir,
        unique_name
    )

    with zipfile.ZipFile(
        zip_path,
        "w",
        zipfile.ZIP_DEFLATED
    ) as zipf:

        for root, dirs, files in os.walk(
            backup_folder
        ):

            for file in files:

                full_path = os.path.join(
                    root,
                    file
                )

                arcname = os.path.relpath(
                    full_path,
                    backup_folder
                )

                zipf.write(
                    full_path,
                    arcname
                )

    return zip_path


def already_sent(backup_id):

    return SMBTransfer.query.filter_by(
        backup_id=backup_id,
        status="success"
    ).first()


def ensure_smb_dir(
    conn,
    share,
    path
):

    parts = path.split("/")

    current = ""

    for part in parts:

        if current:
            current += "/" + part
        else:
            current = part

        try:

            conn.createDirectory(
                share,
                current
            )

        except Exception:
            pass


def upload_backup_to_smb(
    backup_id,
    conn=None
):

    b = Backup.query.filter_by(
        backup_id=backup_id
    ).first()

    if not b:

        return {
            "success": False,
            "message": "Backup not found"
        }

    if already_sent(backup_id):

        return {
            "success": True,
            "message": "Already sent"
        }

    zip_path = None

    local_conn = False

    try:

        backup_folder = (
            Path(STEGO_DIR)
            / b.year
            / b.month
            / backup_id
        )

        if not backup_folder.exists():

            raise Exception(
                "Backup folder not found"
            )

        zip_path = create_backup_zip(
            backup_folder,
            backup_id
        )

        if conn is None:

            conn = create_smb_connection()
            local_conn = True

        smb_folder = f"{b.year}/{b.month}"

        cfg = _get_smb_session()
        if cfg and cfg.get("share"):
            share = cfg["share"]
        else:
            share = os.getenv("SMB_SHARE")

        if not share:
            raise Exception("SMB share not set (session or env).")

        ensure_smb_dir(
            conn,
            share,
            smb_folder
        )

        remote_file = (
            f"{smb_folder}/{backup_id}.zip"
        )

        with open(zip_path, "rb") as f:

            conn.storeFile(
                share,
                remote_file,
                f
            )

        transfer = SMBTransfer(
            backup_id=backup_id,
            switch_id=b.switch_id,
            smb_path=remote_file,
            status="success",
            message="Backup uploaded successfully",
            created_at=datetime.utcnow()
        )

        db.session.add(transfer)
        db.session.commit()

        smb_log(
            switch_id=b.switch_id,
            switch_name=(
                b.switch.name
                if b.switch else "Unknown"
            ),
            level="info",
            status="success",
            message=f"[SMB] Uploaded: {remote_file}",
            file_path=remote_file
        )

        return {
            "success": True,
            "message": "Backup uploaded successfully"
        }

    except Exception as e:

        transfer = SMBTransfer(
            backup_id=backup_id,
            switch_id=b.switch_id,
            status="failed",
            message=str(e)
        )

        db.session.add(transfer)
        db.session.commit()

        smb_log(
            switch_id=b.switch_id,
            switch_name=(
                b.switch.name
                if b.switch else "Unknown"
            ),
            level="error",
            status="failed",
            message=f"[SMB] Upload failed: {e}",
            file_path=backup_id
        )

        return {
            "success": False,
            "message": str(e)
        }

    finally:

        try:

            if local_conn and conn:
                conn.close()

        except Exception:
            pass

        try:

            if zip_path and os.path.exists(zip_path):
                os.remove(zip_path)

        except Exception:
            pass


@smb_bp.route("/smb/send/<backup_id>")
def smb_send_backup(backup_id):

    result = upload_backup_to_smb(
        backup_id
    )

    backup = Backup.query.filter_by(
        backup_id=backup_id
    ).first()

    if result["success"]:

        flash(
            result["message"],
            "success"
        )

    else:

        flash(
            f"SMB Error: {result['message']}",
            "danger"
        )

    return redirect(
        url_for(
            "backup.list_backups",
            switch_id=backup.switch_id
        )
    )


@smb_bp.route(
    "/smb/send-multiple",
    methods=["POST"]
)
def smb_send_multiple():

    backup_ids = request.form.getlist(
        "backup_ids"
    )

    if not backup_ids:

        flash(
            "No backups selected.",
            "warning"
        )

        return redirect(
            request.referrer
        )

    success_count = 0
    failed_count = 0

    conn = None

    try:

        conn = create_smb_connection()

        for backup_id in backup_ids:

            result = upload_backup_to_smb(
                backup_id,
                conn=conn
            )

            if result["success"]:
                success_count += 1
            else:
                failed_count += 1

    finally:

        try:

            if conn:
                conn.close()

        except Exception:
            pass

    flash(
        f"{success_count} backup(s) uploaded successfully.",
        "success"
    )

    if failed_count:

        flash(
            f"{failed_count} backup(s) failed.",
            "danger"
        )

    return redirect(
        url_for(
            "smb.smb_dashboard"
        )
    )


@smb_bp.route("/smb/session", methods=["GET", "POST"])
def smb_session():
    if request.method == "POST":
        server = request.form.get("server", "").strip()
        share = request.form.get("share", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        domain = request.form.get("domain", "").strip()

        if not server or not share or not username or not password:
            flash("Server, share, username and password are required for SMB session.", "danger")
            return redirect(url_for("smb.smb_session"))

        _set_smb_session(
            username=username,
            password=password,
            server=server,
            share=share,
            domain=domain,
        )
        flash(f"SMB session set for {SMB_SESSION_TTL_MINUTES} minutes.", "success")
        return redirect(url_for("smb.smb_dashboard"))

    current = _get_smb_session()
    return render_template("smb_session.html", current=current, ttl=SMB_SESSION_TTL_MINUTES)


@smb_bp.route("/smb/dashboard")
def smb_dashboard():

    backups = Backup.query.order_by(
        Backup.created_at.desc()
    ).all()

    backup_data = []

    for b in backups:

        transfer = SMBTransfer.query.filter_by(
            backup_id=b.backup_id,
            status="success"
        ).first()

        tehran = pytz.timezone("Asia/Tehran")

        backup_time = None
        send_time = None

        if b.created_at:
            backup_time = b.created_at

        if transfer and transfer.created_at:
            send_time = (
                transfer.created_at
                .replace(tzinfo=pytz.utc)
                .astimezone(tehran)
            )

        backup_data.append({
            "backup_id": b.backup_id,
            "switch_name": (
                b.switch.name
                if b.switch else "Unknown"
            ),
            "backup_time": backup_time,
            "smb_send_time": send_time,
            "sent": transfer is not None
        })


    cfg = _get_smb_session()

    expire_time = None

    if cfg:
        tehran = pytz.timezone("Asia/Tehran")
        expire = datetime.fromisoformat(cfg["expires_at"])
        expire_time = expire.replace(tzinfo=pytz.utc).astimezone(tehran)

    return render_template(
        "smb_dashboard.html",
        backups=backup_data,
        smb_expire_time=expire_time
    )


@smb_bp.route("/smb/send-all")
def smb_send_all():

    backups = Backup.query.all()

    pending = []

    for b in backups:

        if not already_sent(
            b.backup_id
        ):
            pending.append(
                b.backup_id
            )

    if not pending:

        flash(
            "No pending backups.",
            "info"
        )

        return redirect(
            url_for(
                "smb.smb_dashboard"
            )
        )

    success = 0
    failed = 0

    conn = None

    try:

        conn = create_smb_connection()

        for backup_id in pending:

            result = upload_backup_to_smb(
                backup_id,
                conn=conn
            )

            if result["success"]:
                success += 1
            else:
                failed += 1

    finally:

        try:

            if conn:
                conn.close()

        except Exception:
            pass

    flash(
        f"{success} backup(s) uploaded.",
        "success"
    )

    if failed:

        flash(
            f"{failed} backup(s) failed.",
            "danger"
        )

    return redirect(
        url_for(
            "smb.smb_dashboard"
        )
    )
