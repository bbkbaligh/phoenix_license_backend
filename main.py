import os
from datetime import datetime
from typing import Optional
from collections import defaultdict

import requests
from fastapi import FastAPI, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr

from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# =========================
#   CONFIG
# =========================

# 1) On Render: DATABASE_URL is automatically provided (postgresql://...)
# 2) Locally: if not set, we fall back to SQLite
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./activations.db"

# Only add connect_args for SQLite
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

# IMPORTANT: for PostgreSQL on Render you MUST have "psycopg2-binary"
# in your requirements.txt, otherwise SQLAlchemy cannot connect.
engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

APP_TITLE = "Phoenix License Tracker"
APP_VERSION = "1.0.0"


# =========================
#   SQLALCHEMY MODELS
# =========================

class Activation(Base):
    __tablename__ = "activations"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String, index=True)
    app_version = Column(String, index=True)
    license_scope = Column(String, index=True)
    license_key = Column(String, index=True)
    fingerprint = Column(String, index=True)

    user_first_name = Column(String, nullable=True)
    user_last_name = Column(String, nullable=True)
    user_email = Column(String, nullable=True)
    user_phone = Column(String, nullable=True)

    activated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class RevokedLicenseMachine(Base):
    """
    Révocation par PAIRE (license_key + fingerprint).
    """
    __tablename__ = "revoked_license_machines"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, index=True)
    fingerprint = Column(String, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)


class UsageEvent(Base):
    """
    Log d'usage :
    - APP_OPEN
    - MODULE_OPEN
    - CHATBOT_CALL
    - LICENSE_ACTIVATION
    etc.
    """
    __tablename__ = "usage_events"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String, index=True)
    app_version = Column(String, index=True)
    license_key = Column(String, index=True)
    fingerprint = Column(String, index=True)

    event_type = Column(String, index=True)
    event_source = Column(String, index=True)

    details = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# =========================
#   FASTAPI APP
# =========================

app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
#   Pydantic Schemas
# =========================

class UserIn(BaseModel):
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    email: Optional[EmailStr] = None
    phone: Optional[str] = ""


class ActivationIn(BaseModel):
    app_id: str
    app_version: str
    license_scope: str
    license_key: str
    fingerprint: str
    activated_at: int  # timestamp (secondes UTC)
    expires_at: int    # timestamp (secondes UTC)
    user: UserIn


class ActivationOut(BaseModel):
    activation_id: int
    total_activations: int
    machine_activations: int
    is_first_activation_for_machine: bool


class UsageEventIn(BaseModel):
    app_id: str
    app_version: str
    license_key: Optional[str] = None
    fingerprint: Optional[str] = None
    event_type: str          # APP_OPEN, MODULE_OPEN, CHATBOT_CALL, ...
    event_source: str        # StartWindow, ChatBotWidget, MapAssistant, ...
    details: Optional[str] = None


# =========================
#   Telegram helper
# =========================

def send_telegram_message(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[telegram] not configured (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)")
        return

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"[telegram] error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[telegram] exception while sending message: {e}")


# =========================
#   ROUTES: CORE
# =========================

@app.get("/health")
def health():
    return {"status": "ok", "version": APP_VERSION}


@app.post("/activation", response_model=ActivationOut)
def register_activation(data: ActivationIn, db: Session = Depends(get_db)):
    """
    Enregistre UNE activation supplémentaire.
    """
    activation = Activation(
        app_id=data.app_id,
        app_version=data.app_version,
        license_scope=data.license_scope,
        license_key=data.license_key,
        fingerprint=data.fingerprint,
        user_first_name=data.user.first_name or "",
        user_last_name=data.user.last_name or "",
        user_email=str(data.user.email) if data.user.email else None,
        user_phone=data.user.phone or "",
        activated_at=datetime.utcfromtimestamp(data.activated_at),
        expires_at=datetime.utcfromtimestamp(data.expires_at),
        created_at=datetime.utcnow(),
    )

    db.add(activation)
    db.commit()
    db.refresh(activation)

    total = db.query(Activation).count()

    machine_count = (
        db.query(Activation)
        .filter(Activation.fingerprint == data.fingerprint)
        .count()
    )
    is_first_for_machine = machine_count == 1

    title = "🆕 New machine activation" if is_first_for_machine else "♻️ Re-activation on existing machine"

    full_name = f"{data.user.first_name or ''} {data.user.last_name or ''}".strip() or "Unknown user"
    email = data.user.email or "N/A"

    msg_lines = [
        title,
        "",
        f"App: {data.app_id} v{data.app_version}",
        f"Scope: {data.license_scope}",
        f"License key: {data.license_key}",
        "",
        f"Machine ID (fingerprint): {data.fingerprint}",
        f"User: {full_name}",
        f"Email: {email}",
        f"Phone: {data.user.phone or 'N/A'}",
        "",
        f"Activated at: {datetime.utcfromtimestamp(data.activated_at).isoformat()}",
        f"Expires at:  {datetime.utcfromtimestamp(data.expires_at).isoformat()}",
        "",
        f"➡ Global activations (all machines): {total}",
        f"➡ Activations for this machine: {machine_count}",
    ]

    if not is_first_for_machine:
        msg_lines.append(f"ℹ This is activation #{machine_count} for this PC.")

    send_telegram_message("\n".join(msg_lines))

    return ActivationOut(
        activation_id=activation.id,
        total_activations=total,
        machine_activations=machine_count,
        is_first_activation_for_machine=is_first_for_machine,
    )


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(Activation).count()
    return {"total_activations": total}


@app.get("/stats/machine/{fingerprint}")
def stats_machine(fingerprint: str, db: Session = Depends(get_db)):
    machine_count = (
        db.query(Activation)
        .filter(Activation.fingerprint == fingerprint)
        .count()
    )
    return {
        "fingerprint": fingerprint,
        "activations": machine_count,
    }


# =========================
#   RÉVOCATION (Option B)
# =========================

@app.api_route("/revoke/{license_key}/{fingerprint}", methods=["GET", "POST"])
def revoke_license_on_machine(
    license_key: str,
    fingerprint: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    existing = (
        db.query(RevokedLicenseMachine)
        .filter(
            RevokedLicenseMachine.license_key == license_key,
            RevokedLicenseMachine.fingerprint == fingerprint,
        )
        .first()
    )

    if existing:
        status = "already_revoked"
    else:
        rev = RevokedLicenseMachine(
            license_key=license_key,
            fingerprint=fingerprint,
        )
        db.add(rev)
        db.commit()
        status = "revoked"

        send_telegram_message(
            f"⛔ License revoked on machine\n\n"
            f"License key: {license_key}\n"
            f"Fingerprint: {fingerprint}\n"
            f"Status: {status}"
        )

    method = request.method if request else "UNKNOWN"

    return {
        "status": status,
        "license_key": license_key,
        "fingerprint": fingerprint,
        "via": method,
    }


@app.api_route("/unrevoke/{license_key}/{fingerprint}", methods=["GET", "POST"])
def unrevoke_license_on_machine(
    license_key: str,
    fingerprint: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    """
    Annule la révocation pour une PAIRE (license_key + fingerprint).

    Après cet appel, /license/status/{license_key}/{fingerprint}
    renverra {"revoked": false} si aucune autre entrée n'existe.
    """

    existing = (
        db.query(RevokedLicenseMachine)
        .filter(
            RevokedLicenseMachine.license_key == license_key,
            RevokedLicenseMachine.fingerprint == fingerprint,
        )
        .first()
    )

    if not existing:
        status = "not_revoked"
    else:
        db.delete(existing)
        db.commit()
        status = "unrevoked"

        send_telegram_message(
            f"✅ License UNREVOKED on machine\n\n"
            f"License key: {license_key}\n"
            f"Fingerprint: {fingerprint}\n"
            f"Status: {status}"
        )

    method = request.method if request else "UNKNOWN"

    return {
        "status": status,
        "license_key": license_key,
        "fingerprint": fingerprint,
        "via": method,
    }


# ========= LICENSE STATUS (nouveau endpoint + compat) =========

@app.get("/license/status")
def license_status_query(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Vérifie si une paire (license_key, fingerprint) est révoquée.

    Utilisation moderne (client Phoenix) :
        GET /license/status?license_key=...&fingerprint=...
    """
    revoked = (
        db.query(RevokedLicenseMachine)
        .filter(
            RevokedLicenseMachine.license_key == license_key,
            RevokedLicenseMachine.fingerprint == fingerprint,
        )
        .first()
        is not None
    )
    return {
        "license_key": license_key,
        "fingerprint": fingerprint,
        "revoked": revoked,
    }


@app.get("/license/status/{license_key}/{fingerprint}")
def license_status(
    license_key: str,
    fingerprint: str,
    db: Session = Depends(get_db),
):
    """
    Compatibilité avec l'ancien client qui appelait :
        /license/status/<license_key>/<fingerprint>
    """
    return license_status_query(license_key=license_key, fingerprint=fingerprint, db=db)


# =========================
#   ROUTES: USAGE TRACKING
# =========================

@app.post("/usage")
def register_usage(event: UsageEventIn, db: Session = Depends(get_db)):
    row = UsageEvent(
        app_id=event.app_id,
        app_version=event.app_version,
        license_key=event.license_key or "",
        fingerprint=event.fingerprint or "",
        event_type=event.event_type,
        event_source=event.event_source,
        details=event.details or "",
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {"status": "ok", "id": row.id}


# =========================
#   ROUTES ADMIN (JSON)
# =========================

@app.get("/admin/activations")
def admin_list_activations(db: Session = Depends(get_db)):
    rows = (
        db.query(Activation)
        .order_by(Activation.created_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "app_id": r.app_id,
            "app_version": r.app_version,
            "license_scope": r.license_scope,
            "license_key": r.license_key,
            "fingerprint": r.fingerprint,
            "user_first_name": r.user_first_name,
            "user_last_name": r.user_last_name,
            "user_email": r.user_email,
            "user_phone": r.user_phone,
            "activated_at": r.activated_at.isoformat() if r.activated_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@app.get("/admin/licenses")
def admin_list_licenses(db: Session = Depends(get_db)):
    rows = db.query(Activation).all()

    per_license = defaultdict(lambda: {
        "license_key": None,
        "total_activations": 0,
        "unique_machines": set(),
        "first_activation_at": None,
        "last_activation_at": None,
    })

    for r in rows:
        lk = r.license_key or "UNKNOWN"
        entry = per_license[lk]
        entry["license_key"] = lk
        entry["total_activations"] += 1
        if r.fingerprint:
            entry["unique_machines"].add(r.fingerprint)

        if r.activated_at:
            if entry["first_activation_at"] is None or r.activated_at < entry["first_activation_at"]:
                entry["first_activation_at"] = r.activated_at
            if entry["last_activation_at"] is None or r.activated_at > entry["last_activation_at"]:
                entry["last_activation_at"] = r.activated_at

    result = []
    for lk, entry in per_license.items():
        result.append({
            "license_key": lk,
            "total_activations": entry["total_activations"],
            "unique_machines": len(entry["unique_machines"]),
            "first_activation_at": entry["first_activation_at"].isoformat() if entry["first_activation_at"] else None,
            "last_activation_at": entry["last_activation_at"].isoformat() if entry["last_activation_at"] else None,
        })

    result.sort(key=lambda x: x["total_activations"], reverse=True)
    return result


@app.get("/admin/revocations")
def admin_list_revocations(db: Session = Depends(get_db)):
    rows = (
        db.query(RevokedLicenseMachine)
        .order_by(RevokedLicenseMachine.revoked_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "license_key": r.license_key,
            "fingerprint": r.fingerprint,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
        }
        for r in rows
    ]


@app.get("/admin/machines")
def admin_list_machines(db: Session = Depends(get_db)):
    rows = db.query(Activation).all()

    per_machine = defaultdict(lambda: {
        "fingerprint": None,
        "licenses": set(),
        "total_activations": 0,
        "first_activation_at": None,
        "last_activation_at": None,
    })

    for r in rows:
        fp = r.fingerprint or "UNKNOWN"
        entry = per_machine[fp]
        entry["fingerprint"] = fp
        entry["total_activations"] += 1
        if r.license_key:
            entry["licenses"].add(r.license_key)

        if r.activated_at:
            if entry["first_activation_at"] is None or r.activated_at < entry["first_activation_at"]:
                entry["first_activation_at"] = r.activated_at
            if entry["last_activation_at"] is None or r.activated_at > entry["last_activation_at"]:
                entry["last_activation_at"] = r.activated_at

    result = []
    for fp, entry in per_machine.items():
        result.append({
            "fingerprint": fp,
            "total_activations": entry["total_activations"],
            "licenses": sorted(list(entry["licenses"])),
            "first_activation_at": entry["first_activation_at"].isoformat() if entry["first_activation_at"] else None,
            "last_activation_at": entry["last_activation_at"].isoformat() if entry["last_activation_at"] else None,
        })

    result.sort(key=lambda x: x["total_activations"], reverse=True)
    return result


@app.get("/admin/usage/recent")
def admin_usage_recent(limit: int = 100, db: Session = Depends(get_db)):
    rows = (
        db.query(UsageEvent)
        .order_by(UsageEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "app_id": r.app_id,
            "app_version": r.app_version,
            "license_key": r.license_key,
            "fingerprint": r.fingerprint,
            "event_type": r.event_type,
            "event_source": r.event_source,
            "details": r.details,
        }
        for r in rows
    ]


@app.get("/admin/usage/stats/by-type")
def admin_usage_stats_by_type(db: Session = Depends(get_db)):
    rows = (
        db.query(UsageEvent.event_type, func.count(UsageEvent.id))
        .group_by(UsageEvent.event_type)
        .all()
    )
    return [
        {"event_type": etype, "count": count}
        for (etype, count) in rows
    ]


# =========================
#   DASHBOARD HTML /admin
# =========================

BASE_ADMIN_CSS = """
    body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background-color: #0f172a;
        color: #e5e7eb;
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 24px;
    }
    h1 { font-size: 28px; margin-bottom: 8px; }
    h2 { margin-top: 32px; margin-bottom: 8px; font-size: 20px; }
    .subtitle { color: #9ca3af; margin-bottom: 24px; }
    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }
    .card {
        background-color: #111827;
        border-radius: 10px;
        padding: 16px;
        border: 1px solid #1f2937;
    }
    .card-title {
        font-size: 14px;
        color: #9ca3af;
    }
    .card-value {
        font-size: 24px;
        font-weight: 600;
        margin-top: 4px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 13px;
    }
    th, td {
        padding: 6px 8px;
        border-bottom: 1px solid #1f2937;
    }
    th {
        text-align: left;
        background-color: #111827;
        font-weight: 600;
        font-size: 12px;
        color: #9ca3af;
    }
    tr:nth-child(even) td { background-color: #020617; }
    tr:nth-child(odd)  td { background-color: #030712; }
    .badge {
        display: inline-block;
        border-radius: 999px;
        padding: 2px 8px;
        font-size: 11px;
    }
    .badge-green { background-color: #16a34a33; color: #4ade80; }
    .badge-blue  { background-color: #1d4ed833; color: #60a5fa; }
    .badge-red   { background-color: #b91c1c33; color: #fca5a5; }
    .small { font-size: 11px; color: #9ca3af; }
    a { color: #93c5fd; text-decoration: none; }
    a:hover { text-decoration: underline; }
    canvas { max-width: 100%; margin-top: 8px; }
    .breadcrumbs { font-size: 13px; margin-bottom: 12px; color: #9ca3af; }
"""


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(db: Session = Depends(get_db)):
    total_activations = db.query(Activation).count()
    total_machines = db.query(Activation.fingerprint).distinct().count()
    total_revocations = db.query(RevokedLicenseMachine).count()
    total_usage_events = db.query(UsageEvent).count()

    last_activations = (
        db.query(Activation)
        .order_by(Activation.created_at.desc())
        .limit(20)
        .all()
    )

    last_usage = (
        db.query(UsageEvent)
        .order_by(UsageEvent.created_at.desc())
        .limit(50)
        .all()
    )

    stats_by_type = (
        db.query(UsageEvent.event_type, func.count(UsageEvent.id))
        .group_by(UsageEvent.event_type)
        .all()
    )
    labels = [row[0] for row in stats_by_type]
    counts = [row[1] for row in stats_by_type]

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phoenix License Tracker – Admin</title>
    <style>
        {BASE_ADMIN_CSS}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="container">
    <h1>Phoenix License Tracker – Admin</h1>
    <div class="subtitle">
        Version {APP_VERSION} • {datetime.utcnow().isoformat().split('.')[0]}Z
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Total activations</div>
            <div class="card-value">{total_activations}</div>
        </div>
        <div class="card">
            <div class="card-title">Unique machines</div>
            <div class="card-value">{total_machines}</div>
        </div>
        <div class="card">
            <div class="card-title">Revoked pairs</div>
            <div class="card-value">{total_revocations}</div>
        </div>
        <div class="card">
            <div class="card-title">Usage events</div>
            <div class="card-value">{total_usage_events}</div>
        </div>
    </div>

    <h2>Usage by event type</h2>
    <div class="card">
        <div class="small">APP_OPEN, LICENSE_ACTIVATION, CHATBOT_CALL, MODULE_OPEN, ...</div>
        <canvas id="usageChart" height="120"></canvas>
    </div>

    <h2>Last activations</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>License key</th>
                    <th>Fingerprint</th>
                    <th>User</th>
                    <th>Activated at</th>
                    <th>Expires at</th>
                </tr>
            </thead>
            <tbody>
    """

    for r in last_activations:
        user_name = ((r.user_first_name or "") + " " + (r.user_last_name or "")).strip() or "—"
        act = r.activated_at.isoformat() if r.activated_at else ""
        exp = r.expires_at.isoformat() if r.expires_at else ""
        html += f"""
                <tr>
                    <td>{r.id}</td>
                    <td>
                        <a href="/admin/license/{r.license_key}" class="badge badge-blue">{r.license_key}</a>
                    </td>
                    <td>
                        <a href="/admin/machine/{r.fingerprint}" class="badge badge-green">{r.fingerprint}</a>
                    </td>
                    <td>{user_name}</td>
                    <td>{act}</td>
                    <td>{exp}</td>
                </tr>
        """

    html += """
            </tbody>
        </table>
        <div class="small">
            Full JSON: <a href="/admin/activations" target="_blank">/admin/activations</a>
        </div>
    </div>
    """

    html += """
    <h2>Last usage events</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>License key</th>
                    <th>Fingerprint</th>
                    <th>Created at</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    """

    for u in last_usage:
        created = u.created_at.isoformat() if u.created_at else ""
        details = (u.details or "")[:80]
        if len(u.details or "") > 80:
            details += "..."
        html += f"""
                <tr>
                    <td>{u.id}</td>
                    <td><span class="badge badge-blue">{u.event_type}</span></td>
                    <td>{u.event_source}</td>
                    <td class="small">
                        <a href="/admin/license/{u.license_key}" target="_blank">{u.license_key}</a>
                    </td>
                    <td class="small">
                        <a href="/admin/machine/{u.fingerprint}" target="_blank">{u.fingerprint}</a>
                    </td>
                    <td>{created}</td>
                    <td class="small">{details}</td>
                </tr>
        """

    labels_js = "[" + ",".join(f"'{l}'" for l in labels) + "]"
    counts_js = "[" + ",".join(str(c) for c in counts) + "]"

    html += f"""
            </tbody>
        </table>
        <div class="small">
            Full JSON: <a href="/admin/usage/recent" target="_blank">/admin/usage/recent</a>
        </div>
    </div>

    <h2>Raw Admin APIs</h2>
    <div class="card">
        <div class="small">
            <ul>
                <li><a href="/admin/activations" target="_blank">/admin/activations</a></li>
                <li><a href="/admin/licenses" target="_blank">/admin/licenses</a></li>
                <li><a href="/admin/machines" target="_blank">/admin/machines</a></li>
                <li><a href="/admin/revocations" target="_blank">/admin/revocations</a></li>
                <li><a href="/admin/usage/recent" target="_blank">/admin/usage/recent</a></li>
                <li><a href="/admin/usage/stats/by-type" target="_blank">/admin/usage/stats/by-type</a></li>
            </ul>
        </div>
    </div>

</div>

<script>
    const labels = {labels_js};
    const dataCounts = {counts_js};

    const ctx = document.getElementById('usageChart').getContext('2d');
    const usageChart = new Chart(ctx, {{
        type: 'bar',
        data: {{
            labels: labels,
            datasets: [{{
                label: 'Events count',
                data: dataCounts,
            }}]
        }},
        options: {{
            plugins: {{
                legend: {{
                    labels: {{
                        color: '#e5e7eb'
                    }}
                }}
            }},
            scales: {{
                x: {{
                    ticks: {{
                        color: '#9ca3af'
                    }},
                    grid: {{
                        color: '#1f2937'
                    }}
                }},
                y: {{
                    ticks: {{
                        color: '#9ca3af'
                    }},
                    grid: {{
                        color: '#1f2937'
                    }}
                }}
            }}
        }}
    }});
</script>

</body>
</html>
"""
    return HTMLResponse(content=html)


# =========================
#   MACHINE DETAIL PAGE
# =========================

@app.get("/admin/machine/{fingerprint}", response_class=HTMLResponse)
def admin_machine_detail(fingerprint: str, db: Session = Depends(get_db)):
    activations = (
        db.query(Activation)
        .filter(Activation.fingerprint == fingerprint)
        .order_by(Activation.activated_at.asc())
        .all()
    )

    usage = (
        db.query(UsageEvent)
        .filter(UsageEvent.fingerprint == fingerprint)
        .order_by(UsageEvent.created_at.desc())
        .limit(200)
        .all()
    )

    revoked = (
        db.query(RevokedLicenseMachine)
        .filter(RevokedLicenseMachine.fingerprint == fingerprint)
        .all()
    )

    total_activations = len(activations)
    licenses = sorted({a.license_key for a in activations if a.license_key})
    first_act = activations[0].activated_at.isoformat() if activations and activations[0].activated_at else "—"
    last_act = activations[-1].activated_at.isoformat() if activations and activations[-1].activated_at else "—"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Machine {fingerprint} – Phoenix Admin</title>
    <style>{BASE_ADMIN_CSS}</style>
</head>
<body>
<div class="container">
    <div class="breadcrumbs">
        <a href="/admin">Admin</a> · Machine
    </div>
    <h1>Machine details</h1>
    <div class="subtitle">
        Fingerprint: <span class="badge badge-green">{fingerprint}</span>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Total activations</div>
            <div class="card-value">{total_activations}</div>
        </div>
        <div class="card">
            <div class="card-title">Licenses used</div>
            <div class="card-value">{len(licenses)}</div>
        </div>
        <div class="card">
            <div class="card-title">First activation</div>
            <div class="card-value" style="font-size:13px;">{first_act}</div>
        </div>
        <div class="card">
            <div class="card-title">Last activation</div>
            <div class="card-value" style="font-size:13px;">{last_act}</div>
        </div>
    </div>

    <h2>Licenses on this machine</h2>
    <div class="card">
        <ul class="small">
    """
    for lk in licenses:
        html += f'<li><a href="/admin/license/{lk}">{lk}</a></li>'
    if not licenses:
        html += "<li>No license recorded yet.</li>"
    html += """
        </ul>
    </div>

    <h2>Activations history</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>License key</th>
                    <th>User</th>
                    <th>Activated at</th>
                    <th>Expires at</th>
                </tr>
            </thead>
            <tbody>
    """
    for a in activations:
        user_name = ((a.user_first_name or "") + " " + (a.user_last_name or "")).strip() or "—"
        act = a.activated_at.isoformat() if a.activated_at else ""
        exp = a.expires_at.isoformat() if a.expires_at else ""
        html += f"""
                <tr>
                    <td>{a.id}</td>
                    <td><a href="/admin/license/{a.license_key}" class="badge badge-blue">{a.license_key}</a></td>
                    <td>{user_name}</td>
                    <td>{act}</td>
                    <td>{exp}</td>
                </tr>
        """
    html += """
            </tbody>
        </table>
    </div>

    <h2>Usage events on this machine</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>License key</th>
                    <th>Created at</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    """
    for u in usage:
        created = u.created_at.isoformat() if u.created_at else ""
        details = (u.details or "")[:80]
        if len(u.details or "") > 80:
            details += "..."
        html += f"""
                <tr>
                    <td>{u.id}</td>
                    <td><span class="badge badge-blue">{u.event_type}</span></td>
                    <td>{u.event_source}</td>
                    <td class="small"><a href="/admin/license/{u.license_key}">{u.license_key}</a></td>
                    <td>{created}</td>
                    <td class="small">{details}</td>
                </tr>
        """
    html += """
            </tbody>
        </table>
    </div>
"""

    if revoked:
        html += """
    <h2>Revocations for this machine</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>License key</th>
                    <th>Revoked at</th>
                </tr>
            </thead>
            <tbody>
        """
        for r in revoked:
            rev_at = r.revoked_at.isoformat() if r.revoked_at else ""
            html += f"""
                <tr>
                    <td>{r.id}</td>
                    <td><a href="/admin/license/{r.license_key}">{r.license_key}</a></td>
                    <td>{rev_at}</td>
                </tr>
            """
        html += """
            </tbody>
        </table>
    </div>
"""

    html += """
</div>
</body>
</html>
"""
    return HTMLResponse(content=html)


# =========================
#   LICENSE DETAIL PAGE
# =========================

@app.get("/admin/license/{license_key:path}", response_class=HTMLResponse)
 def admin_license_detail(license_key: str, db: Session = Depends(get_db)):
    activations = (
        db.query(Activation)
        .filter(Activation.license_key == license_key)
        .order_by(Activation.activated_at.asc())
        .all()
    )

    usage = (
        db.query(UsageEvent)
        .filter(UsageEvent.license_key == license_key)
        .order_by(UsageEvent.created_at.desc())
        .limit(200)
        .all()
    )

    revoked_pairs = (
        db.query(RevokedLicenseMachine)
        .filter(RevokedLicenseMachine.license_key == license_key)
        .all()
    )

    total_activations = len(activations)
    machines = sorted({a.fingerprint for a in activations if a.fingerprint})
    first_act = activations[0].activated_at.isoformat() if activations and activations[0].activated_at else "—"
    last_act = activations[-1].activated_at.isoformat() if activations and activations[-1].activated_at else "—"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>License {license_key} – Phoenix Admin</title>
    <style>{BASE_ADMIN_CSS}</style>
</head>
<body>
<div class="container">
    <div class="breadcrumbs">
        <a href="/admin">Admin</a> · License
    </div>
    <h1>License details</h1>
    <div class="subtitle">
        License key: <span class="badge badge-blue">{license_key}</span>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Total activations</div>
            <div class="card-value">{total_activations}</div>
        </div>
        <div class="card">
            <div class="card-title">Unique machines</div>
            <div class="card-value">{len(machines)}</div>
        </div>
        <div class="card">
            <div class="card-title">First activation</div>
            <div class="card-value" style="font-size:13px;">{first_act}</div>
        </div>
        <div class="card">
            <div class="card-title">Last activation</div>
            <div class="card-value" style="font-size:13px;">{last_act}</div>
        </div>
    </div>

    <h2>Machines using this license</h2>
    <div class="card">
        <ul class="small">
    """
    for fp in machines:
        html += f'<li><a href="/admin/machine/{fp}">{fp}</a></li>'
    if not machines:
        html += "<li>No machine recorded yet.</li>"
    html += """
        </ul>
    </div>

    <h2>Activations for this license</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Fingerprint</th>
                    <th>User</th>
                    <th>Activated at</th>
                    <th>Expires at</th>
                </tr>
            </thead>
            <tbody>
    """
    for a in activations:
        user_name = ((a.user_first_name or "") + " " + (a.user_last_name or "")).strip() or "—"
        act = a.activated_at.isoformat() if a.activated_at else ""
        exp = a.expires_at.isoformat() if a.expires_at else ""
        html += f"""
                <tr>
                    <td>{a.id}</td>
                    <td><a href="/admin/machine/{a.fingerprint}" class="badge badge-green">{a.fingerprint}</a></td>
                    <td>{user_name}</td>
                    <td>{act}</td>
                    <td>{exp}</td>
                </tr>
        """
    html += """
            </tbody>
        </table>
    </div>

    <h2>Usage events for this license</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Fingerprint</th>
                    <th>Created at</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    """
    for u in usage:
        created = u.created_at.isoformat() if u.created_at else ""
        details = (u.details or "")[:80]
        if len(u.details or "") > 80:
            details += "..."
        html += f"""
                <tr>
                    <td>{u.id}</td>
                    <td><span class="badge badge-blue">{u.event_type}</span></td>
                    <td>{u.event_source}</td>
                    <td class="small"><a href="/admin/machine/{u.fingerprint}">{u.fingerprint}</a></td>
                    <td>{created}</td>
                    <td class="small">{details}</td>
                </tr>
        """
    html += """
            </tbody>
        </table>
    </div>
"""

    if revoked_pairs:
        html += """
    <h2>Revocations for this license</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Fingerprint</th>
                    <th>Revoked at</th>
                </tr>
            </thead>
            <tbody>
        """
        for r in revoked_pairs:
            rev_at = r.revoked_at.isoformat() if r.revoked_at else ""
            html += f"""
                <tr>
                    <td>{r.id}</td>
                    <td><a href="/admin/machine/{r.fingerprint}">{r.fingerprint}</a></td>
                    <td>{rev_at}</td>
                </tr>
            """
        html += """
            </tbody>
        </table>
    </div>
"""

    html += """
</div>
</body>
</html>
"""
    return HTMLResponse(content=html)
