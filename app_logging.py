# app_logging.py
from models import Log, db
from flask import request, session, has_request_context

def _get_client_ip():
   
    try:
        if not has_request_context():
            return None

        # اگر چند IP باشد، اولین IP معمولاً کلاینت واقعی است
        xff = request.headers.get("X-Forwarded-For", "") or request.headers.get(
            "X-Real-IP", ""
        )
        if xff:
            return xff.split(",")[0].strip()

        return request.remote_addr
    except Exception:
        return None


def log_event(
    level: str = "INFO",
    message: str = "",
    switch=None,
    status: str | None = None,
    file_path: str | None = None,
    event_type: str | None = None,
):
    
    try:
        # مقادیر مربوط به کاربر و کلاینت
        user_id = None
        username = None
        ip_address = None
        user_agent = None

        if has_request_context():
            try:
                user_id = session.get("user_id")
                username = session.get("username")
            except Exception:
                # اگر session مشکل داشت، نگذار کل سیستم کرش کند
                user_id = None
                username = None

            try:
                ip_address = _get_client_ip()
                user_agent = request.headers.get("User-Agent", "")
            except Exception:
                ip_address = None
                user_agent = None

        # اطلاعات سوئیچ (اگر وجود داشته باشد)
        switch_id = None
        switch_name = None
        if switch is not None:
            try:
                switch_id = getattr(switch, "id", None)
                switch_name = getattr(switch, "name", None)
            except Exception:
                switch_id = None
                switch_name = None

        log = Log(
            switch_id=switch_id,
            switch_name=switch_name,
            level=level,
            status=status,
            message=message,
            file_path=file_path,
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        db.session.add(log)
        db.session.commit()

    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass