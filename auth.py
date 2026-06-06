from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User

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
            flash("Invalid username or password", "danger")
            return render_template("login.html")

        if not user.check_password(password):
            flash("Invalid username or password", "danger")
            return render_template("login.html")

        session["user_id"] = user.id
        session["username"] = user.username

        flash("Login successful", "success")

        return redirect(url_for("list_switches"))

    return render_template("login.html")


# -----------------------
# LOGOUT
# -----------------------

@auth_bp.route("/logout")
def logout():

    session.clear()

    flash("Logged out", "info")

    return redirect(url_for("auth.login"))
