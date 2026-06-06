from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from zoneinfo import ZoneInfo
from security import encrypt, decrypt
from flask_login import UserMixin

TEHRAN_TZ = ZoneInfo("Asia/Tehran")

db = SQLAlchemy()


class CredentialProfile(db.Model):
    __tablename__ = "credential_profile"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    secret = db.Column(db.String(120), nullable=True)
    description = db.Column(db.Text)

    snmp_version    = db.Column(db.Integer, default=2, nullable=False)
    snmp_community  = db.Column(db.String(255), nullable=True)
    snmp_auth_proto = db.Column(db.String(10),  nullable=True)
    snmp_auth_key   = db.Column(db.String(255), nullable=True)
    snmp_priv_proto = db.Column(db.String(10),  nullable=True)
    snmp_priv_key   = db.Column(db.String(255), nullable=True)

    def set_snmp_community(self, raw):
        self.snmp_community = encrypt(raw).decode() if raw else None

    def get_snmp_community(self):
        return decrypt(self.snmp_community.encode()) if self.snmp_community else None

    def set_snmp_auth_key(self, raw):
        self.snmp_auth_key = encrypt(raw).decode() if raw else None

    def get_snmp_auth_key(self):
        return decrypt(self.snmp_auth_key.encode()) if self.snmp_auth_key else None

    def set_snmp_priv_key(self, raw):
        self.snmp_priv_key = encrypt(raw).decode() if raw else None

    def get_snmp_priv_key(self):
        return decrypt(self.snmp_priv_key.encode()) if self.snmp_priv_key else None

    def set_password(self, raw):
        self.password = encrypt(raw).decode()

    def get_password(self):
        return decrypt(self.password.encode())

    def set_secret(self, raw):
        if raw:
            self.secret = encrypt(raw).decode()
        else:
            self.secret = None

    def get_secret(self):
        if not self.secret:
            return None
        return decrypt(self.secret.encode())

    switches = db.relationship("Switch", backref="profile", lazy=True)

    def __repr__(self):
        return f"<CredentialProfile {self.name}>"


class Location(db.Model):
    __tablename__ = "locations"

    id = db.Column(db.Integer, primary_key=True)
    building = db.Column(db.String(100), nullable=False)
    floor = db.Column(db.String(50), nullable=True)
    unit = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    switches = db.relationship("Switch", backref="location", lazy=True)

    def __repr__(self):
        parts = [self.building]
        if self.floor:
            parts.append(self.floor)
        if self.unit:
            parts.append(self.unit)
        return " / ".join(parts)

    @property
    def full_path(self):
        return self.__repr__()


class Switch(db.Model):
    __tablename__ = "switch"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    ip = db.Column(db.String(45), unique=True)
    device_type = db.Column(db.String(80))
    location_name = db.Column(db.String(120))

    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("credential_profile.id"), nullable=True)

    groups = db.Column(db.String(200))
    status = db.Column(db.String(20), default="offline")
    description = db.Column(db.Text)


class Log(db.Model):
    __tablename__ = "log"

    id          = db.Column(db.Integer, primary_key=True)
    switch_id   = db.Column(db.Integer, db.ForeignKey("switch.id"))
    switch_name = db.Column(db.String(120))
    level       = db.Column(db.String(20))
    status      = db.Column(db.String(20))
    message     = db.Column(db.Text)
    file_path   = db.Column(db.String(255))
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(TEHRAN_TZ))

    switch = db.relationship("Switch", backref="logs")


class ScheduledJob(db.Model):
    __tablename__ = "scheduled_job"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(120), unique=True, nullable=False)
    switch_id = db.Column(db.Integer, db.ForeignKey("switch.id"), nullable=False)
    trigger_type = db.Column(db.String(20), nullable=False)
    interval_seconds = db.Column(db.Integer, nullable=True)
    hour = db.Column(db.Integer, nullable=True)
    minute = db.Column(db.Integer, nullable=True)
    day_of_week = db.Column(db.Integer, nullable=True)
    day_of_month = db.Column(db.Integer, nullable=True)
    last_run = db.Column(db.DateTime, nullable=True)
    switch_ip = db.Column(db.String(15), nullable=False)

    switch = db.relationship(
        "Switch",
        backref=db.backref("jobs", cascade="all, delete-orphan")
    )


class Backup(db.Model):
    __tablename__ = "backups"
    
    id = db.Column(db.Integer, primary_key=True)
    backup_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    switch_id = db.Column(db.Integer, db.ForeignKey("switch.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(TEHRAN_TZ), index=True)
    year = db.Column(db.String(4), nullable=False)
    month = db.Column(db.String(2), nullable=False)
    
    switch = db.relationship("Switch", backref=db.backref("backups", cascade="all, delete-orphan"))


from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_enc = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="admin")

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(TEHRAN_TZ)
    )

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)
        self.password_enc = encrypt(raw_password).decode()

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self):
        return f"<User {self.username}>"


class VisioProject(db.Model):
    __tablename__ = "visio_projects"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    tag = db.Column(db.String(50))
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(TEHRAN_TZ)
    )

    nodes = db.relationship(
        "VisioNode",
        backref="project",
        cascade="all, delete-orphan",
        lazy=True
    )

    links = db.relationship(
        "VisioLink",
        backref="project",
        cascade="all, delete-orphan",
        lazy=True
    )


class VisioNode(db.Model):
    __tablename__ = "visio_nodes"

    id = db.Column(db.Integer, primary_key=True)

    project_id = db.Column(
        db.Integer,
        db.ForeignKey("visio_projects.id"),
        nullable=False
    )

    label = db.Column(db.String(120))

    switch_id = db.Column(
        db.Integer,
        db.ForeignKey("switch.id"),
        nullable=True
    )

    x = db.Column(db.Float, default=100)
    y = db.Column(db.Float, default=100)

    shape = db.Column(db.String(20), default="rect")
    color = db.Column(db.String(20), default="#4F46E5")

    switch = db.relationship("Switch")


class VisioLink(db.Model):
    __tablename__ = "visio_links"

    id = db.Column(db.Integer, primary_key=True)

    project_id = db.Column(
        db.Integer,
        db.ForeignKey("visio_projects.id"),
        nullable=False
    )

    from_node_id = db.Column(
        db.Integer,
        db.ForeignKey("visio_nodes.id"),
        nullable=False
    )

    to_node_id = db.Column(
        db.Integer,
        db.ForeignKey("visio_nodes.id"),
        nullable=False
    )

    from_port = db.Column(db.String(50))
    to_port = db.Column(db.String(50))

    link_type = db.Column(db.String(20), default="ethernet")
    status = db.Column(db.String(20), default="up")

    from_node = db.relationship("VisioNode", foreign_keys=[from_node_id])
    to_node = db.relationship("VisioNode", foreign_keys=[to_node_id])


class SMBTransfer(db.Model):

    __tablename__ = "smb_transfers"

    id = db.Column(db.Integer, primary_key=True)

    backup_id = db.Column(
        db.String(64),
        nullable=False,
        index=True
    )

    switch_id = db.Column(
        db.Integer,
        db.ForeignKey("switch.id"),
        nullable=False
    )

    smb_path = db.Column(db.String(255))
    status = db.Column(db.String(20))
    message = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(TEHRAN_TZ)
    )

    switch = db.relationship(
        "Switch",
        backref=db.backref("smb_transfers", cascade="all, delete-orphan")
    )

class MacAddressLog(db.Model):
    __tablename__ = "mac_address_log"

    id = db.Column(db.Integer, primary_key=True)
    switch_id = db.Column(db.Integer, db.ForeignKey("switch.id"), nullable=False)
    mac = db.Column(db.String(32), index=True)
    vlan = db.Column(db.String(32))
    port = db.Column(db.String(64))
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)

class PortSecLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    switch_id = db.Column(db.Integer, db.ForeignKey('switch.id'), nullable=False)
    mac = db.Column(db.String(20), nullable=False)
    port = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<PortSecLog {self.mac} on {self.port}>'

