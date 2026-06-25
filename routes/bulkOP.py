import json
from datetime import datetime
from flask import Blueprint, render_template, request, Response, stream_with_context
from connection import get_connection
from models import Switch, db, Location, Log
from auth import auth_bp 
from auth_required import login_required

bulk_bp = Blueprint("bulk_operations", __name__, url_prefix="/bulk-operations")

def run_on_switch(ip, username, password, secret, commands):
    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "secret": secret if secret else password,
        "conn_timeout": 20,
        "timeout": 20,
        "fast_cli": False,
    }
    
    try:
        conn = get_connection(device)
        
        if not conn:
            return False, "Connection Error (SSH & Telnet failed)"
            
        with conn:
            conn.enable()
            for cmd in commands:
                conn.send_config_set([cmd], cmd_verify=False)
            conn.save_config()
            
        return True, "Success"
        
    except Exception as e:
        return False, str(e)

@bulk_bp.route("/", methods=["GET"])
@login_required
def bulk_operations():
    switches = Switch.query.order_by(Switch.name.asc()).all()
    buildings = db.session.query(Location.building).distinct().order_by(Location.building.asc()).all()
    unique_buildings = [b[0] for b in buildings if b[0]]
    return render_template("bulk_operations.html", switches=switches, buildings=unique_buildings)

@bulk_bp.route("/run_bulk", methods=["POST"])
@login_required
def run_bulk():
    switch_ids = request.form.getlist("switch_ids")
    operation = request.form.get("operation")
    
    op_data = {
        "new_user": request.form.get("new_user"),
        "new_pass": request.form.get("new_pass"),
        "priv": request.form.get("privilege", "15"),
        "del_user": request.form.get("del_user")
    }

    def generate():
        from app import app
        with app.app_context():
            total = len(switch_ids)
            for index, sid in enumerate(switch_ids):
                sw = Switch.query.get(sid)
                current_progress = int(((index + 1) / total) * 100)
                
                if not sw:
                    continue

                if operation == "add_user":
                    cmds = [f"username {op_data['new_user']} privilege {op_data['priv']} secret {op_data['new_pass']}"]
                    log_label = f"BULK_ADD_USER: username={op_data['new_user']}"
                else:
                    cmds = [f"no username {op_data['del_user']}"]
                    log_label = f"BULK_DELETE_USER: username={op_data['del_user']}"

                if sw.profile:
                    username = sw.profile.username
                    password = sw.profile.get_password()
                    secret = sw.profile.get_secret()

                    # اصلاح‌شده:
                    ok, res = run_on_switch(sw.ip, username, password, secret, cmds)
                else:
                    ok, res = False, "No Credential Profile"

                log = Log(
                    level="INFO" if ok else "error",
                    switch_name=sw.name,
                    status="Success" if ok else "Failed",
                    message=f"{log_label} → {res}"
                )
                db.session.add(log)
                db.session.commit()

                yield f"data: {json.dumps({'name': sw.name, 'ip': sw.ip, 'ok': ok, 'msg': res, 'progress': current_progress})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
