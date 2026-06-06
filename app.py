import os
import io
import subprocess
import uuid
import pandas as pd
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    send_file,
    send_from_directory,
    abort,
    session,
)
from fpdf import FPDF
from flask_wtf import FlaskForm
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from wtforms import (
    StringField,
    PasswordField,
    SelectField,
    TextAreaField,
    SubmitField,
    IntegerField,
)
from wtforms.validators import DataRequired, IPAddress, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.executors.pool import ThreadPoolExecutor
from models import (
    db,
    CredentialProfile,
    Location,
    Switch,
    Log,
    ScheduledJob,
    User,
)
import logging
from dotenv import load_dotenv
load_dotenv()
logging.basicConfig(level=logging.INFO)
logging.getLogger("apscheduler").setLevel(logging.DEBUG)
from routes.bulkOP import bulk_bp
from routes.topology import topology_bp
from smbsync.smb import smb_bp
from smbsync.recovery_smb import recovery_smb_bp
from backup import backup_bp, backup_running_config
from auth import auth_bp
from app_logging import log_event
from auth_required import login_required
from macsec.macsearch import macsec_bp, scan_switch
from macsec.portsec import portsec_bp

TEHRAN_TZ = ZoneInfo("Asia/Tehran")


class Config:
    SECRET_KEY = "dev-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///switches.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False



app = Flask(__name__)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_DURATION"] = 86400
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = None
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR2 = os.path.join(app.root_path, "Dataset")
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
app.register_blueprint(bulk_bp)
app.register_blueprint(backup_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(topology_bp)
app.register_blueprint(smb_bp)
app.register_blueprint(recovery_smb_bp)
app.register_blueprint(macsec_bp)
app.register_blueprint(portsec_bp)
executors = {"default": ThreadPoolExecutor(10)}
scheduler = BackgroundScheduler(executors=executors, timezone=TEHRAN_TZ)
scheduler.start()

@app.before_request
def require_login():
    allowed = ["auth.login"]  # صفحاتی که بدون لاگین آزادند
    if request.endpoint not in allowed and "user_id" not in session:
        return redirect(url_for("auth.login"))

# ===================== FORMS =====================
DEVICE_TYPES = [
    ("cisco_ios", "Cisco IOS"),
]


class SwitchForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    ip = StringField("IP", validators=[DataRequired(), IPAddress()])
    device_type = SelectField("Device", choices=DEVICE_TYPES)
    profile_id = SelectField(
        "Credential Profile", coerce=int, validators=[Optional()]
    )
    location_id = SelectField(
        "Location", coerce=int, validators=[Optional()]
    )
    groups = StringField("Groups")
    status = SelectField(
        "Status",
        choices=[("Online", "Online"), ("Offline", "Offline")],
    )
    description = TextAreaField("Description")
    submit = SubmitField("Save")


class JobForm(FlaskForm):
    switch_id = SelectField("Switch", coerce=int, validators=[DataRequired()])
    trigger_type = SelectField(
        "Trigger Type",
        choices=[
            ("interval", "Interval"),
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ],
        validators=[DataRequired()],
    )
    interval_seconds = IntegerField(
        "Interval (seconds)", validators=[Optional()]
    )
    hour = IntegerField("Hour (0-23)", validators=[Optional()])
    minute = IntegerField("Minute (0-59)", validators=[Optional()])
    day_of_week = IntegerField(
        "Day of week (0=Mon ... 6=Sun)", validators=[Optional()]
    )
    day_of_month = IntegerField(
        "Day of month (1-31)", validators=[Optional()]
    )
    submit = SubmitField("Create Job")


class CredentialProfileForm(FlaskForm):
    name = StringField("Profile Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    secret = PasswordField("Secret (Enable Password)")
    description = TextAreaField("Description")
    submit = SubmitField("Save")


class LocationForm(FlaskForm):
    building = StringField("Building", validators=[DataRequired()])
    floor = StringField("Floor", validators=[Optional()])
    unit = StringField("Unit", validators=[Optional()])
    description = TextAreaField("Description", validators=[Optional()])
    submit = SubmitField("Save")


# ===================== HELPERS =====================

def start_mac_scheduler(app):
    # برای هر سوئیچ
    for sw in Switch.query.all():
        schedule_job(
            job_id=f"macscan:{sw.id}",
            func=scan_switch,
            trigger=IntervalTrigger(minutes=3, timezone=TEHRAN_TZ),
            args=[app, sw.id],
        )



# ✅ تنها تغییر مهم اینجاست: امضای schedule_job تمیز و مینیمال شد
def schedule_job(job_id, func, trigger, args=None):
    scheduler.add_job(
        func=func,
        trigger=trigger,
        id=job_id,
        args=args or [],
        replace_existing=True,
    )


def ping_ip(ip):
    cmd = ["ping", "-c", "3", ip]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=3
        )
        return {"ok": res.returncode == 0, "output": res.stdout + res.stderr}
    except Exception as e:
        return {"ok": False, "output": str(e)}


def log_event(
    level="INFO",
    message="",
    status=None,
    switch=None,
    file_path=None,
    event_type="system",
):
    try:
        sw_id = None
        sw_name = None
        if switch:
            sw_id = switch.id
            sw_name = switch.name
        try:
            _ = request.remote_addr  # فقط برای تست context
        except Exception:
            pass
        log = Log(
            switch_id=sw_id,
            switch_name=sw_name,
            level=level,
            status=status,
            message=f"[{event_type}] {message}",
            file_path=file_path,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print("LOG ERROR:", e)

def run_backup_job(switch_id, job_id):
    result = backup_running_config(switch_id)

    if result.get("success"):
        with app.app_context():
            sj = ScheduledJob.query.filter_by(job_id=job_id).first()
            if sj:
                sj.last_run = datetime.now(TEHRAN_TZ)
                db.session.commit()

def restore_jobs():
    with app.app_context():
        jobs = ScheduledJob.query.all()
        for sj in jobs:
            if sj.trigger_type == "interval" and sj.interval_seconds:
                trigger = IntervalTrigger(seconds=sj.interval_seconds)
            elif (
                sj.trigger_type == "daily"
                and sj.hour is not None
                and sj.minute is not None
            ):
                trigger = CronTrigger(hour=sj.hour, minute=sj.minute)
            elif sj.trigger_type == "weekly":
                trigger = CronTrigger(
                    day_of_week=sj.day_of_week,
                    hour=sj.hour,
                    minute=sj.minute,
                )
            elif sj.trigger_type == "monthly":
                trigger = CronTrigger(
                    day=sj.day_of_month,
                    hour=sj.hour,
                    minute=sj.minute,
                )
            else:
                continue

            # ✅ این خط با امضای جدید هماهنگ شد
            schedule_job(
                sj.job_id,
                backup_running_config,
                trigger,
                args=[sj.switch_id],
            )

            log_event(
                level="INFO",
                message=f"Job restored {sj.job_id}",
                status="restored",
                event_type="scheduler",
            )
            print("restored", sj.job_id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# ===================== ROUTES =====================

@app.route("/")
@login_required
def index():
    return redirect(url_for("list_switches"))


@app.route("/switches")
@login_required
def list_switches():
    return render_template(
        "switches.html", switches=Switch.query.all()
    )


@app.route("/switches/new", methods=["GET", "POST"])
@login_required
def new_switch():
    form = SwitchForm()
    form.profile_id.choices = [(0, "-- Select Profile --")] + [
        (p.id, p.name) for p in CredentialProfile.query.all()
    ]
    locations = Location.query.order_by(
        Location.building, Location.floor, Location.unit
    ).all()
    form.location_id.choices = [(0, "-- Select Location --")] + [
        (loc.id, loc.full_path) for loc in locations
    ]
    if form.validate_on_submit():
        sw = Switch(
            name=form.name.data,
            ip=form.ip.data,
            device_type=form.device_type.data,
            profile_id=(
                form.profile_id.data
                if form.profile_id.data != 0
                else None
            ),
            location_name=(
                Location.query.get(form.location_id.data).full_path
                if form.location_id.data != 0
                else None
            ),
            location_id=(
                form.location_id.data
                if form.location_id.data != 0
                else None
            ),
            groups=form.groups.data,
            status=form.status.data,
            description=form.description.data,
        )
        db.session.add(sw)
        db.session.commit()
        flash("✅ New Switch added Succssefuly", "success")
        return redirect(url_for("list_switches"))
    return render_template("create_switch.html", form=form)


@app.route("/ping_check")
def ping_check():
    ip = request.args.get("ip")
    if not ip:
        return {"ok": False}
    try:
        res = subprocess.run(
            ["ping", "-c", "1", ip],
            capture_output=True,
            timeout=2,
        )
        return {"ok": res.returncode == 0}
    except Exception:
        return {"ok": False}


@app.route("/switches/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_switch(id):
    sw = Switch.query.get_or_404(id)
    form = SwitchForm(obj=sw)
    form.profile_id.choices = [
        (p.id, f"{p.name} ({p.username})")
        for p in CredentialProfile.query.all()
    ]
    form.profile_id.choices.insert(0, (0, "No Profile Selected"))
    locations = Location.query.order_by(
        Location.building, Location.floor, Location.unit
    ).all()
    form.location_id.choices = [(0, "-- Select Location --")] + [
        (loc.id, loc.full_path) for loc in locations
    ]
    if form.validate_on_submit():
        sw.name = form.name.data
        sw.ip = form.ip.data
        sw.device_type = form.device_type.data
        sw.profile_id = (
            form.profile_id.data if form.profile_id.data else None
        )
        sw.location_name = (
            Location.query.get(form.location_id.data).full_path
            if form.location_id.data != 0
            else None
        )
        sw.location_id = (
            form.location_id.data
            if form.location_id.data != 0
            else None
        )
        sw.groups = form.groups.data
        sw.status = form.status.data
        sw.description = form.description.data
        db.session.commit()
        flash("Switch updated", "success")
        return redirect(url_for("list_switches"))
    if request.method == "GET" and sw.location_id:
        form.location_id.data = sw.location_id
    if request.method == "GET" and sw.profile_id:
        form.profile_id.data = sw.profile_id
    return render_template("edit_switch.html", form=form, switch=sw)


@app.route("/switches/delete/<int:id>", methods=["POST"])
@login_required
def delete_switch(id):
    sw = Switch.query.get_or_404(id)

    storage_root = os.path.join(app.root_path, "StegoStorage")

    for backup in sw.backups:
        backup_path = os.path.join(
            storage_root,
            str(backup.year),
            str(backup.month),
            str(backup.id)
        )
        if os.path.exists(backup_path):
            shutil.rmtree(backup_path)

    db.session.delete(sw)
    db.session.commit()

    flash("Switch deleted", "success")
    return redirect(url_for("list_switches"))



@app.route("/jobs")
@login_required
def list_jobs():
    sort = request.args.get("sort", "id")
    order = request.args.get("order", "asc")  # asc یا desc

    jobs = ScheduledJob.query.all()
    display = []

    for j in jobs:
        sw = Switch.query.get(j.switch_id)
        sched_job = scheduler.get_job(j.job_id)

        # NEXT RUN — حذف timezone
        if sched_job and sched_job.next_run_time:
            next_run = sched_job.next_run_time.replace(tzinfo=None)
        else:
            next_run = None

        # LAST RUN — حذف microseconds
        if j.last_run:
            last_run = j.last_run.replace(microsecond=0)
        else:
            last_run = None

        display.append(
            {
                "id": j.job_id,
                "switch_name": sw.name if sw else "Unknown",
                "switch_ip": sw.ip if sw else j.switch_ip,
                "trigger_str": "Interval" if j.trigger_type == "interval" else "Daily",
                "last_run": last_run,
                "next_run_time": next_run,
            }
        )

    # ---------- سورت ----------
    reverse = (order == "desc")

    if sort == "name":
        key = lambda x: x["switch_name"] or ""
    elif sort == "ip":
        key = lambda x: x["switch_ip"] or ""
    elif sort == "trigger":
        key = lambda x: x["trigger_str"] or ""
    elif sort == "last_run":
        key = lambda x: x["last_run"] or datetime.min
    elif sort == "next_run":
        key = lambda x: x["next_run_time"] or datetime.min
    else:
        key = lambda x: x["id"]

    display_sorted = sorted(display, key=key, reverse=reverse)

    return render_template("jobs.html", jobs=display_sorted, sort=sort, order=order)

@app.route("/jobs/new", methods=["GET", "POST"])
@login_required
def new_job():
    form = JobForm()

    # لیست سوییچ‌ها در dropdown
    switches = Switch.query.all()
    form.switch_id.choices = [(sw.id, sw.name) for sw in switches]

    # ------ بخش اضافه‌شده (فقط همین 5 خط) ------
    # مقداردهی اولیه dropdown اگر از صفحه سوییچ‌ها switch_id پاس داده شده
    if request.method == "GET":
        switch_id = request.args.get("switch_id", type=int)
        if switch_id:
            form.switch_id.data = switch_id
    # ----------------------------------------------

    # ادامه‌ی منطق اصلی (دست‌نخورده)
    if form.validate_on_submit():
        sw = Switch.query.get(form.switch_id.data)
        if not sw:
            flash("Switch not found", "danger")
            return redirect(url_for("new_job"))

        job_id = f"job_{sw.id}_{uuid.uuid4().hex[:6]}"

        if form.trigger_type.data == "interval":
            if not form.interval_seconds.data:
                flash("Interval required", "danger")
                return render_template("new_job.html", form=form)
            trigger = IntervalTrigger(seconds=form.interval_seconds.data)

        elif form.trigger_type.data == "daily":
            trigger = CronTrigger(
                hour=form.hour.data,
                minute=form.minute.data
            )

        elif form.trigger_type.data == "weekly":
            trigger = CronTrigger(
                day_of_week=form.day_of_week.data,
                hour=form.hour.data,
                minute=form.minute.data,
            )

        elif form.trigger_type.data == "monthly":
            trigger = CronTrigger(
                day=form.day_of_month.data,
                hour=form.hour.data,
                minute=form.minute.data,
            )

        else:
            flash("Invalid", "danger")
            return render_template("new_job.html", form=form)

        # ادامه کد تو برای ساخت job ...
        # (طبق نسخه‌ی فایل app.py)
        ...
    

        # ✅ این فراخوانی با امضای جدید هماهنگ شد
        schedule_job(
            job_id,
            run_backup_job,
            trigger,
            args=[sw.id, job_id],
        )

        sj = ScheduledJob(
            job_id=job_id,
            switch_id=sw.id,
            switch_ip=sw.ip,
            trigger_type=form.trigger_type.data,
            interval_seconds=form.interval_seconds.data,
            hour=form.hour.data,
            minute=form.minute.data,
            day_of_week=form.day_of_week.data,
            day_of_month=form.day_of_month.data,
            last_run=None,
        )
        db.session.add(sj)
        db.session.commit()
        log_event(
            level="INFO",
            message=f"Job created trigger={form.trigger_type.data}",
            switch=sw,
            status="created",
            event_type="job",
        )
        flash("Job created", "success")
        return redirect(url_for("list_jobs"))
    return render_template("new_job.html", form=form)


@app.route("/jobs/edit/<job_id>", methods=["GET", "POST"])
@login_required
def edit_job(job_id):
    sj = ScheduledJob.query.filter_by(job_id=job_id).first_or_404()
    form = JobForm()
    form.switch_id.choices = [
        (sw.id, sw.name) for sw in Switch.query.all()
    ]
    if request.method == "GET":
        form.switch_id.data = sj.switch_id
        form.trigger_type.data = sj.trigger_type
        form.interval_seconds.data = sj.interval_seconds
        form.hour.data = sj.hour
        form.minute.data = sj.minute
    if form.validate_on_submit():
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass
        if form.trigger_type.data == "interval":
            trigger = IntervalTrigger(
                seconds=form.interval_seconds.data
            )
        else:
            trigger = CronTrigger(
                hour=form.hour.data, minute=form.minute.data
            )

        # ✅ این فراخوانی هم با امضای جدید هماهنگ شد
        schedule_job(
            job_id,
            backup_running_config,
            trigger,
            args=[form.switch_id.data],
        )

        sj.switch_id = form.switch_id.data
        sj.interval_seconds = form.interval_seconds.data
        sj.hour = form.hour.data
        sj.minute = form.minute.data
        sj.trigger_type = form.trigger_type.data
        db.session.commit()
        flash("Job updated", "success")
        return redirect(url_for("list_jobs"))
    return render_template(
        "job_form.html", form=form, job=sj
    )


@app.route("/jobs/delete/<job_id>", methods=["POST"])
@login_required
def delete_job(job_id):
    # اول از scheduler پاک کن
    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass
    
    # بعد از DB
    sj = ScheduledJob.query.filter_by(job_id=job_id).first()
    if sj:
        db.session.delete(sj)
        db.session.commit()
    
    flash("Job deleted", "success")
    return redirect(url_for("list_jobs"))


@app.route("/logs")
@login_required
def list_logs():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 100))
    switch_name = request.args.get("switch")
    level = request.args.get("level")
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    q = Log.query
    if switch_name:
        q = q.filter(Log.switch_name == switch_name)
    if level:
        q = q.filter(Log.level == level)
    if date_from:
        q = q.filter(Log.created_at >= date_from)
    if date_to:
        q = q.filter(Log.created_at <= date_to)
    logs = q.order_by(Log.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    for l in logs.items:
        l.time = l.created_at.strftime("%Y-%m-%d %H:%M:%S")
        if l.file_path:
            l.filename = os.path.basename(l.file_path)

    return render_template(
        "logs.html",
        logs=logs.items,
        pagination=logs,
        switch_list=[s.name for s in Switch.query.all()],
        levels=["INFO", "warning", "error"],
    )


@app.route("/logs/export/excel")
@login_required
def logs_export_excel():
    q = Log.query.all()
    rows = [
        {
            "time": l.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "level": l.level,
            "switch": l.switch_name,
            "status": l.status,
            "message": l.message,
            "file": l.file_path,
        }
        for l in q
    ]
    df = pd.DataFrame(rows)
    path = "logs_export.csv"
    df.to_csv(path, index=False, encoding="utf-8-sig")
    return send_file(path, as_attachment=True)


@app.route("/logs/export/pdf")
def logs_export_pdf():
    q = Log.query.order_by(Log.created_at.desc()).limit(500).all()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Logs Export", ln=True, align="C")
    pdf.ln(5)
    for l in q:
        line = (
            f"{l.created_at.strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{l.level} | {l.switch_name} | {l.status} | {l.message}"
        )
        pdf.multi_cell(0, 5, txt=line)
    path = "logs_export.pdf"
    pdf.output(path)
    return send_file(path, as_attachment=True)


@app.route("/terminal")
@login_required
def terminal():
    return render_template(
        "terminal.html",
        switches=Switch.query.order_by(Switch.name).all(),
    )


@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping_terminal():
    output = ""
    if request.method == "POST":
        command = request.form.get("command")
        if command:
            parts = command.split()
            if parts[0] == "ping" and len(parts) > 1:
                ip = parts[1]
                r = ping_ip(ip)
                output = r["output"]
            else:
                output = "Unknown command"
    return render_template("ping_terminal.html", output=output)


@app.route("/profiles")
@login_required
def list_profiles():
    profiles = CredentialProfile.query.all()
    return render_template("profiles.html", profiles=profiles)


@app.route("/profiles/new", methods=["GET", "POST"])
@login_required
def new_profile():
    form = CredentialProfileForm()
    if form.validate_on_submit():
        p = CredentialProfile(
            name=form.name.data,              # ← اضافه شود
            username=form.username.data,
            description=form.description.data,
        )
        p.set_password(form.password.data)   # پسورد یوزر روی سوئیچ
        p.set_secret(form.secret.data)       # enable secret / enable password
        db.session.add(p)
        db.session.commit()
        flash("✅ New Profile created", "success")
        return redirect(url_for("list_profiles"))
    return render_template("new_profile.html", form=form)


@app.route("/profiles/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_profile(id):
    p = CredentialProfile.query.get_or_404(id)
    form = CredentialProfileForm(obj=p)
    if form.validate_on_submit():
        p.name = form.name.data
        p.username = form.username.data
        if form.password.data:
            p.set_password(form.password.data)
        p.set_secret(form.secret.data)
        p.description = form.description.data
        db.session.commit()
        flash("✅ Profile updated (Edit)", "success")
        return redirect(url_for("list_profiles"))
    return render_template(
        "edit_profile.html", form=form, profile=p
    )


@app.route("/profiles/delete/<int:id>", methods=["POST"])
@login_required
def delete_profile(id):
    p = CredentialProfile.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    flash("🗑️ Profile Deleted", "success")
    return redirect(url_for("list_profiles"))


@app.route("/locations")
@login_required
def list_locations():
    locations = Location.query.order_by(
        Location.building, Location.floor, Location.unit
    ).all()
    return render_template(
        "locations.html", locations=locations
    )


@app.route("/locations/new", methods=["GET", "POST"])
@login_required
def new_location():
    form = LocationForm()
    if form.validate_on_submit():
        location = Location(
            building=form.building.data,
            floor=form.floor.data,
            unit=form.unit.data,
            description=form.description.data,
        )
        db.session.add(location)
        db.session.commit()
        flash(
            f'Location "{location.full_path}" created successfully!',
            "success",
        )
        return redirect(url_for("list_locations"))
    return render_template("new_location.html", form=form)


@app.route(
    "/locations/<int:location_id>/edit", methods=["GET", "POST"]
)
def edit_location(location_id):
    location = Location.query.get_or_404(location_id)
    form = LocationForm(obj=location)
    if form.validate_on_submit():
        location.building = form.building.data
        location.floor = form.floor.data
        location.unit = form.unit.data
        location.description = form.description.data
        db.session.commit()
        flash(
            f'Location "{location.full_path}" updated successfully!',
            "success",
        )
        return redirect(url_for("list_locations"))
    return render_template(
        "edit_location.html", form=form, location=location
    )


@app.route(
    "/locations/<int:location_id>/delete", methods=["POST"]
)
def delete_location(location_id):
    location = Location.query.get_or_404(location_id)
    path = location.full_path
    db.session.delete(location)
    db.session.commit()
    flash(
        f'Location "{path}" deleted successfully!', "success"
    )
    return redirect(url_for("list_locations"))

@app.route("/api/images")
def list_images():
    try:
        files = [
            f for f in os.listdir(DATASET_DIR2)
            if f.lower().endswith(".jpg")
        ]
        return jsonify(files)
    except FileNotFoundError:
        return jsonify([])

@app.route("/dataset/<path:filename>")
def serve_dataset(filename):
    if not filename.lower().endswith(".jpg"):
        abort(403)
    return send_from_directory(DATASET_DIR2, filename)

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):

            login_user(user, remember=True)

            next_page = request.args.get("next")

            if next_page:
                return redirect(next_page)

            return redirect("/")

        flash("Invalid username or password")

    return render_template("login.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        restore_jobs()
        start_mac_scheduler(app)
    print([j.id for j in scheduler.get_jobs()])

    app.run(host="0.0.0.0", port=15000, debug=True, use_reloader=False)

