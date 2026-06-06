# app_logging.py
from models import Log, db

def log_event(
    level="INFO",
    message="",
    switch=None,
    status=None,
    file_path=None,
    event_type=None,  # فعلاً نادیده گرفته می‌شه
):
    log = Log(
        switch_id=switch.id if switch else None,
        switch_name=switch.name if switch else None,
        level=level,
        status=status,
        message=message,
        file_path=file_path,
    )
    db.session.add(log)
    db.session.commit()
