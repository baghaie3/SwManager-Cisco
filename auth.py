from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User
from app_logging import log_event

auth_bp = Blueprint("auth", __name__)

# -----------------------
# LOGIN PAGE
# -----------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()

        if not user:
            # لاگ لاگین ناموفق - کاربر پیدا نشد
            try:
                log_event(
                    level="WARNING",
                    message=f"Failed login attempt (user not found) username={username}",
                    status="failed",
                    file_path="auth.py",
                    event_type="LoginFailed",
                )
            except Exception:
                pass

            flash("Invalid username or password", "danger")
            return render_template("login.html")

        if not user.check_password(password):
            # لاگ لاگین ناموفق - پسورد اشتباه
            try:
                log_event(
                    level="WARNING",
                    message=f"Failed login attempt (bad password) username={username}",
                    status="failed",
                    file_path="auth.py",
                    event_type="LoginFailed",
                )
            except Exception:
                pass

            flash("Invalid username or password", "danger")
            return render_template("login.html")

        session["user_id"] = user.id
        session["username"] = user.username

        # لاگ لاگین موفق
        try:
            log_event(
                level="INFO",
                message=f"User {user.username} logged in successfully",
                status="Success",
                file_path="auth.py",
                event_type="LoginSuccess",
            )
        except Exception:
            pass

        flash("Login successful", "success")

        return redirect(url_for("list_switches"))

    return render_template("login.html")


# -----------------------
# LOGOUT
# -----------------------

@auth_bp.route("/logout")
def logout():

    username = session.get("username")

    # لاگ قبل از پاک کردن session
    try:
        log_event(
            level="INFO",
            message=f"User {username} logged out",
            status="success",
            file_path="auth.py",
            event_type="auth_logout",
        )
    except Exception:
        pass

    session.clear()

    flash("Logged out", "info")

    return redirect(url_for("auth.login"))