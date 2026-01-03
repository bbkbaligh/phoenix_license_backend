# =========================
#   main.py  (PART 1/3)
# =========================

import os
import json
import time
import hashlib
import secrets
from datetime import datetime
from typing import Optional
from collections import defaultdict
from urllib.parse import quote
from pathlib import Path

import requests
from fastapi import FastAPI, Depends, Request, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, validator

from sqlalchemy import create_engine, Column, Integer, String, DateTime, func, Boolean, Text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy import text as sql_text


# =========================
#   CONFIG
# =========================

DATABASE_URL = os.getenv("DATABASE_URL")

# Render sometimes provides postgres:// instead of postgresql://
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# If Postgres and no sslmode set, add sslmode=require (often needed on managed DB)
if DATABASE_URL and DATABASE_URL.startswith("postgresql://") and "sslmode=" not in DATABASE_URL:
    sep = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL += f"{sep}sslmode=require"

# Local fallback SQLite
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./activations.db"

# Only add connect_args for SQLite
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

APP_TITLE = "Phoenix License Tracker"
APP_VERSION = "1.0.0"

ADMIN_DELETE_SECRET = os.getenv("ADMIN_DELETE_SECRET", "phoenix_super_reset_2024")
ADMIN_DASHBOARD_PASSWORD = os.getenv("ADMIN_DASHBOARD_PASSWORD", "admin123")

CLOUD_SYNC_ENABLED = os.getenv("CLOUD_SYNC_ENABLED", "true").lower() == "true"
CLOUD_SYNC_API_KEY = os.getenv("CLOUD_SYNC_API_KEY", "")
CLOUD_SYNC_ENDPOINT = os.getenv("CLOUD_SYNC_ENDPOINT", "https://api.phoenix-sync.com/v1/sync")


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
    __tablename__ = "revoked_license_machines"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, index=True)
    fingerprint = Column(String, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)


class UsageEvent(Base):
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


class UserAccount(Base):
    __tablename__ = "user_accounts"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String, nullable=True)

    password_hash = Column(String, nullable=False)

    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    company = Column(String, nullable=True)

    cloud_sync_enabled = Column(Boolean, default=True)
    cloud_api_key = Column(String, nullable=True)
    cloud_user_id = Column(String, nullable=True)

    auto_sync = Column(Boolean, default=True)
    sync_frequency = Column(Integer, default=3600)

    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    last_sync = Column(DateTime, nullable=True)

    email_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)

    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    sync_metadata = Column(Text, nullable=True)


class UserSyncLog(Base):
    __tablename__ = "user_sync_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)

    sync_type = Column(String, index=True)
    sync_status = Column(String, index=True)

    items_uploaded = Column(Integer, default=0)
    items_downloaded = Column(Integer, default=0)
    items_modified = Column(Integer, default=0)

    details = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)


class UserLicense(Base):
    __tablename__ = "user_licenses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    license_key = Column(String, index=True)

    is_primary = Column(Boolean, default=False)
    assigned_at = Column(DateTime, default=datetime.utcnow)

    cloud_synced = Column(Boolean, default=False)
    last_sync = Column(DateTime, nullable=True)


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

# ✅ STATIC FILES safe mount (no crash if folder missing)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
else:
    print("[warn] static/ folder missing -> /static not mounted (no crash)")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Ensure tables at startup (avoid import-time crash)
@app.on_event("startup")
def on_startup():
    try:
        with engine.connect() as conn:
            conn.execute(sql_text("SELECT 1"))
        Base.metadata.create_all(bind=engine)
        print("[startup] DB OK, tables ensured.")
    except Exception as e:
        print("[startup] DB init failed:", repr(e))
        raise


# =========================
#   Pydantic Schemas
# =========================

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company: Optional[str] = None

    @validator("password")
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v

class UserLogin(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: str

class UserUpdate(BaseModel):
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company: Optional[str] = None
    cloud_sync_enabled: Optional[bool] = None
    auto_sync: Optional[bool] = None
    sync_frequency: Optional[int] = None

class UserSyncRequest(BaseModel):
    sync_type: str = "full_sync"
    force: bool = False

class UserToken(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    email: str
    is_admin: bool

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
    activated_at: int
    expires_at: int
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
    event_type: str
    event_source: str
    details: Optional[str] = None

class LicenseLifecycleEventIn(BaseModel):
    app_id: str
    app_version: str
    license_key: str
    fingerprint: str
    event_type: str
    details: Optional[str] = None


# =========================
#   UTILITAIRES
# =========================

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256(f"{password}{salt}".encode())
    return f"{hash_obj.hexdigest()}:{salt}"

def verify_password(password: str, password_hash: str) -> bool:
    if ":" not in password_hash:
        return False
    stored_hash, salt = password_hash.split(":", 1)
    hash_obj = hashlib.sha256(f"{password}{salt}".encode())
    return hash_obj.hexdigest() == stored_hash

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

def get_current_user(token: str, db: Session) -> Optional[UserAccount]:
    user = db.query(UserAccount).filter(
        (UserAccount.username == token) | (UserAccount.cloud_api_key == token)
    ).first()
    if user and user.is_active:
        return user
    return None

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

def sync_to_cloud(user_id: int, sync_type: str, db: Session) -> dict:
    if not CLOUD_SYNC_ENABLED or not CLOUD_SYNC_API_KEY:
        return {"status": "cloud_sync_disabled"}

    user = db.query(UserAccount).filter(UserAccount.id == user_id).first()
    if not user or not user.cloud_sync_enabled:
        return {"status": "user_sync_disabled"}

    sync_log = UserSyncLog(
        user_id=user_id,
        sync_type=sync_type,
        sync_status="started",
        started_at=datetime.utcnow()
    )
    db.add(sync_log)
    db.commit()

    try:
        user_data = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "company": user.company,
            "licenses": []
        }

        user_licenses = db.query(UserLicense).filter(
            UserLicense.user_id == user_id
        ).all()

        for ul in user_licenses:
            activations = db.query(Activation).filter(
                Activation.license_key == ul.license_key
            ).all()

            license_data = {
                "license_key": ul.license_key,
                "is_primary": ul.is_primary,
                "activations": []
            }

            for act in activations:
                activation_data = {
                    "app_id": act.app_id,
                    "app_version": act.app_version,
                    "fingerprint": act.fingerprint,
                    "user_first_name": act.user_first_name,
                    "user_last_name": act.user_last_name,
                    "user_email": act.user_email,
                    "activated_at": act.activated_at.isoformat() if act.activated_at else None,
                    "expires_at": act.expires_at.isoformat() if act.expires_at else None
                }
                license_data["activations"].append(activation_data)

            user_data["licenses"].append(license_data)

        headers = {
            "Authorization": f"Bearer {CLOUD_SYNC_API_KEY}",
            "Content-Type": "application/json",
            "X-User-API-Key": user.cloud_api_key or ""
        }

        start_time = time.time()
        response = requests.post(
            f"{CLOUD_SYNC_ENDPOINT}/sync",
            json={
                "user_data": user_data,
                "sync_type": sync_type,
                "timestamp": datetime.utcnow().isoformat()
            },
            headers=headers,
            timeout=30
        )
        duration_ms = int((time.time() - start_time) * 1000)

        if response.status_code == 200:
            result = response.json()
            sync_log.sync_status = "success"
            sync_log.items_uploaded = result.get("items_uploaded", 0)
            sync_log.items_downloaded = result.get("items_downloaded", 0)
            sync_log.details = json.dumps(result)
        else:
            sync_log.sync_status = "failed"
            sync_log.error_message = f"HTTP {response.status_code}: {response.text}"

        sync_log.completed_at = datetime.utcnow()
        sync_log.duration_ms = duration_ms

        user.last_sync = datetime.utcnow()
        db.commit()

        return {
            "status": sync_log.sync_status,
            "items_uploaded": sync_log.items_uploaded,
            "items_downloaded": sync_log.items_downloaded,
            "duration_ms": duration_ms
        }

    except Exception as e:
        sync_log.sync_status = "failed"
        sync_log.error_message = str(e)
        sync_log.completed_at = datetime.utcnow()
        db.commit()
        return {"status": "error", "error": str(e)}
# =========================
#   main.py  (PART 2/3)
# =========================

# =========================
#   ROUTES: USER ACCOUNTS
# =========================

@app.post("/users/register", response_model=UserToken)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(UserAccount).filter(
        (UserAccount.username == user.username) | (UserAccount.email == user.email)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = hash_password(user.password)
    api_key = generate_api_key()

    new_user = UserAccount(
        username=user.username,
        email=user.email,
        password_hash=hashed_password,
        phone=user.phone,
        first_name=user.first_name,
        last_name=user.last_name,
        company=user.company,
        cloud_api_key=api_key,
        verification_token=secrets.token_urlsafe(32),
        created_at=datetime.utcnow()
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    send_telegram_message(
        f"👤 New user registered\n\n"
        f"Username: {user.username}\n"
        f"Email: {user.email}\n"
        f"Name: {user.first_name or ''} {user.last_name or ''}\n"
        f"Company: {user.company or 'N/A'}\n"
        f"Registered at: {datetime.utcnow().isoformat()}"
    )

    return UserToken(
        access_token=api_key,
        user_id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        is_admin=new_user.is_admin
    )

@app.post("/users/login", response_model=UserToken)
def login_user(login: UserLogin, db: Session = Depends(get_db)):
    if login.username:
        user = db.query(UserAccount).filter(UserAccount.username == login.username).first()
    elif login.email:
        user = db.query(UserAccount).filter(UserAccount.email == login.email).first()
    else:
        raise HTTPException(status_code=400, detail="Username or email required")

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    if not verify_password(login.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.last_login = datetime.utcnow()
    db.commit()

    return UserToken(
        access_token=user.cloud_api_key,
        user_id=user.id,
        username=user.username,
        email=user.email,
        is_admin=user.is_admin
    )

@app.get("/users/profile")
def get_user_profile(token: str = Query(...), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_licenses = db.query(UserLicense).filter(
        UserLicense.user_id == user.id
    ).all()

    licenses = []
    for ul in user_licenses:
        activation_count = db.query(Activation).filter(
            Activation.license_key == ul.license_key
        ).count()

        licenses.append({
            "license_key": ul.license_key,
            "is_primary": ul.is_primary,
            "assigned_at": ul.assigned_at.isoformat() if ul.assigned_at else None,
            "activation_count": activation_count,
            "cloud_synced": ul.cloud_synced,
            "last_sync": ul.last_sync.isoformat() if ul.last_sync else None
        })

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "company": user.company,
            "phone": user.phone,
            "is_admin": user.is_admin,
            "is_active": user.is_active,
            "email_verified": user.email_verified,
            "cloud_sync_enabled": user.cloud_sync_enabled,
            "auto_sync": user.auto_sync,
            "sync_frequency": user.sync_frequency,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "last_sync": user.last_sync.isoformat() if user.last_sync else None
        },
        "licenses": licenses
    }

@app.put("/users/profile")
def update_user_profile(update: UserUpdate, token: str = Query(...), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if update.phone is not None:
        user.phone = update.phone
    if update.first_name is not None:
        user.first_name = update.first_name
    if update.last_name is not None:
        user.last_name = update.last_name
    if update.company is not None:
        user.company = update.company
    if update.cloud_sync_enabled is not None:
        user.cloud_sync_enabled = update.cloud_sync_enabled
    if update.auto_sync is not None:
        user.auto_sync = update.auto_sync
    if update.sync_frequency is not None:
        user.sync_frequency = update.sync_frequency

    db.commit()
    return {"status": "updated", "user_id": user.id}

@app.post("/users/sync")
def sync_user_data(sync_request: UserSyncRequest, token: str = Query(...), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not sync_request.force and user.last_sync:
        time_since_sync = (datetime.utcnow() - user.last_sync).total_seconds()
        if time_since_sync < user.sync_frequency:
            return {
                "status": "skipped",
                "message": f"Last sync was {int(time_since_sync)} seconds ago (frequency: {user.sync_frequency}s)"
            }

    result = sync_to_cloud(user.id, sync_request.sync_type, db)

    return {
        "status": "sync_triggered",
        "user_id": user.id,
        "sync_result": result
    }

@app.post("/users/license/assign")
def assign_license_to_user(
    license_key: str = Query(...),
    token: str = Query(...),
    is_primary: bool = Query(False),
    db: Session = Depends(get_db)
):
    user = get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    license_exists = db.query(Activation).filter(
        Activation.license_key == license_key
    ).first()
    if not license_exists:
        raise HTTPException(status_code=404, detail="License key not found")

    existing_assignment = db.query(UserLicense).filter(
        UserLicense.user_id == user.id,
        UserLicense.license_key == license_key
    ).first()
    if existing_assignment:
        raise HTTPException(status_code=400, detail="License already assigned to user")

    if is_primary:
        db.query(UserLicense).filter(
            UserLicense.user_id == user.id,
            UserLicense.is_primary == True
        ).update({"is_primary": False})

    user_license = UserLicense(
        user_id=user.id,
        license_key=license_key,
        is_primary=is_primary,
        assigned_at=datetime.utcnow()
    )

    db.add(user_license)
    db.commit()

    if user.auto_sync and user.cloud_sync_enabled:
        sync_to_cloud(user.id, "upload", db)

    return {
        "status": "assigned",
        "license_key": license_key,
        "user_id": user.id,
        "is_primary": is_primary
    }

@app.get("/users/sync/history")
def get_sync_history(token: str = Query(...), limit: int = Query(50, ge=1, le=1000), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    sync_logs = db.query(UserSyncLog).filter(
        UserSyncLog.user_id == user.id
    ).order_by(UserSyncLog.started_at.desc()).limit(limit).all()

    return [
        {
            "id": log.id,
            "sync_type": log.sync_type,
            "sync_status": log.sync_status,
            "items_uploaded": log.items_uploaded,
            "items_downloaded": log.items_downloaded,
            "items_modified": log.items_modified,
            "started_at": log.started_at.isoformat() if log.started_at else None,
            "completed_at": log.completed_at.isoformat() if log.completed_at else None,
            "duration_ms": log.duration_ms,
            "error_message": log.error_message
        }
        for log in sync_logs
    ]


# =========================
#   ROUTES: CORE
# =========================

@app.get("/health")
def health():
    return {"status": "ok", "version": APP_VERSION}

@app.post("/activation", response_model=ActivationOut)
def register_activation(data: ActivationIn, db: Session = Depends(get_db)):
    existing_pair_count = (
        db.query(Activation)
        .filter(
            Activation.license_key == data.license_key,
            Activation.fingerprint == data.fingerprint,
        )
        .count()
    )
    is_first_for_pair = existing_pair_count == 0

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

    auto_revoked = False
    if not is_first_for_pair:
        existing_rev = (
            db.query(RevokedLicenseMachine)
            .filter(
                RevokedLicenseMachine.license_key == data.license_key,
                RevokedLicenseMachine.fingerprint == data.fingerprint,
            )
            .first()
        )
        if not existing_rev:
            rev = RevokedLicenseMachine(
                license_key=data.license_key,
                fingerprint=data.fingerprint,
            )
            db.add(rev)
            db.commit()
            auto_revoked = True

            send_telegram_message(
                "⚠️ License key reused on the same machine → auto-revocation\n\n"
                f"License key: {data.license_key}\n"
                f"Fingerprint: {data.fingerprint}\n"
                f"Total activations for this pair: {existing_pair_count + 1}"
            )

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
    if auto_revoked:
        msg_lines.append("⛔ This license key has been reused on this machine and was automatically revoked.")

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
    return {"fingerprint": fingerprint, "activations": machine_count}


# =========================
#   RÉVOCATION
# =========================

def _revoke_pair_core(license_key: str, fingerprint: str, db: Session, method: str):
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
        rev = RevokedLicenseMachine(license_key=license_key, fingerprint=fingerprint)
        db.add(rev)
        db.commit()
        status = "revoked"

        send_telegram_message(
            f"⛔ License revoked on machine\n\n"
            f"License key: {license_key}\n"
            f"Fingerprint: {fingerprint}\n"
            f"Status: {status}"
        )

    return {"status": status, "license_key": license_key, "fingerprint": fingerprint, "via": method}

@app.api_route("/revoke", methods=["GET", "POST"])
def revoke_license_on_machine(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
    request: Request = None,
):
    method = request.method if request else "UNKNOWN"
    return _revoke_pair_core(license_key, fingerprint, db, method)

@app.api_route("/revoke/{path_data:path}", methods=["GET", "POST"])
def revoke_license_on_machine_compat(
    path_data: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    if "/" not in path_data:
        raise HTTPException(status_code=400, detail="Invalid revoke path")
    license_key, fingerprint = path_data.rsplit("/", 1)
    method = request.method if request else "UNKNOWN"
    return _revoke_pair_core(license_key, fingerprint, db, method)

def _unrevoke_pair_core(license_key: str, fingerprint: str, db: Session, method: str):
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

    return {"status": status, "license_key": license_key, "fingerprint": fingerprint, "via": method}

@app.api_route("/unrevoke", methods=["GET", "POST"])
def unrevoke_license_on_machine(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
    request: Request = None,
):
    method = request.method if request else "UNKNOWN"
    return _unrevoke_pair_core(license_key, fingerprint, db, method)

@app.api_route("/unrevoke/{path_data:path}", methods=["GET", "POST"])
def unrevoke_license_on_machine_compat(
    path_data: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    if "/" not in path_data:
        raise HTTPException(status_code=400, detail="Invalid unrevoke path")
    license_key, fingerprint = path_data.rsplit("/", 1)
    method = request.method if request else "UNKNOWN"
    return _unrevoke_pair_core(license_key, fingerprint, db, method)


# =========================
#   LICENSE STATUS + LIFECYCLE
# =========================

@app.get("/license/status")
def license_status_query(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
):
    revoked = (
        db.query(RevokedLicenseMachine)
        .filter(
            RevokedLicenseMachine.license_key == license_key,
            RevokedLicenseMachine.fingerprint == fingerprint,
        )
        .first()
        is not None
    )
    return {"license_key": license_key, "fingerprint": fingerprint, "revoked": revoked}

@app.get("/license/status/{license_key}/{fingerprint}")
def license_status_compat(license_key: str, fingerprint: str, db: Session = Depends(get_db)):
    return license_status_query(license_key=license_key, fingerprint=fingerprint, db=db)

@app.post("/license/event")
def license_lifecycle_event(event: LicenseLifecycleEventIn, db: Session = Depends(get_db)):
    row = UsageEvent(
        app_id=event.app_id,
        app_version=event.app_version,
        license_key=event.license_key,
        fingerprint=event.fingerprint,
        event_type=event.event_type,
        event_source="PhoenixClient",
        details=event.details or "",
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    if event.event_type == "LICENSE_DELETED_LOCAL":
        title = "🗑 License deleted locally by user"
    elif event.event_type == "LICENSE_EXPIRED_LOCAL":
        title = "⌛ License expired on client (local cleanup done)"
    elif event.event_type == "LICENSE_REVOKED_REMOTE":
        title = "⛔ License revoked remotely (client cleaned local files)"
    else:
        title = "⚠️ License lifecycle event"

    msg_lines = [
        title,
        "",
        f"Event type: {event.event_type}",
        "",
        f"App: {event.app_id} v{event.app_version}",
        f"License key: {event.license_key}",
        f"Machine ID (fingerprint): {event.fingerprint}",
        "",
        f"Details: {event.details or 'N/A'}",
        "",
        f"(UsageEvent ID: {row.id})",
    ]
    send_telegram_message("\n".join(msg_lines))
    return {"status": "ok", "id": row.id}


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
#   ADMIN DELETE / RESET
# =========================

@app.post("/admin/delete-all")
def admin_delete_all(secret: str = Query(...), db: Session = Depends(get_db)):
    if not ADMIN_DELETE_SECRET:
        raise HTTPException(status_code=500, detail="ADMIN_DELETE_SECRET not configured")
    if secret != ADMIN_DELETE_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    deleted_usage = db.query(UsageEvent).delete()
    deleted_revocations = db.query(RevokedLicenseMachine).delete()
    deleted_activations = db.query(Activation).delete()
    deleted_user_licenses = db.query(UserLicense).delete()
    deleted_sync_logs = db.query(UserSyncLog).delete()
    deleted_users = db.query(UserAccount).delete()

    db.commit()

    send_telegram_message(
        f"⚠️ ADMIN DELETE ALL\n\n"
        f"Deleted activations: {deleted_activations}\n"
        f"Deleted usage events: {deleted_usage}\n"
        f"Deleted revocations: {deleted_revocations}\n"
        f"Deleted users: {deleted_users}\n"
        f"Deleted user_licenses: {deleted_user_licenses}\n"
        f"Deleted user_sync_logs: {deleted_sync_logs}"
    )

    return {
        "status": "ok",
        "deleted_activations": deleted_activations,
        "deleted_usage_events": deleted_usage,
        "deleted_revocations": deleted_revocations,
        "deleted_users": deleted_users,
        "deleted_user_licenses": deleted_user_licenses,
        "deleted_user_sync_logs": deleted_sync_logs,
    }

@app.get("/admin/reset-db")
def admin_reset_db(token: str = Query(...), db: Session = Depends(get_db)):
    if token != ADMIN_DELETE_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")
    return admin_delete_all(secret=token, db=db)

@app.post("/admin/confirm-delete")
def admin_confirm_delete(password: str = Query(...), db: Session = Depends(get_db)):
    if password != ADMIN_DASHBOARD_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin password")
    return admin_delete_all(secret=ADMIN_DELETE_SECRET, db=db)


# =========================
#   ROUTES ADMIN (JSON)
# =========================

@app.get("/admin/activations")
def admin_list_activations(db: Session = Depends(get_db)):
    rows = db.query(Activation).order_by(Activation.created_at.desc()).all()
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
    rows = db.query(RevokedLicenseMachine).order_by(RevokedLicenseMachine.revoked_at.desc()).all()
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
    rows = db.query(UsageEvent).order_by(UsageEvent.created_at.desc()).limit(limit).all()
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
    rows = db.query(UsageEvent.event_type, func.count(UsageEvent.id)).group_by(UsageEvent.event_type).all()
    return [{"event_type": etype, "count": count} for (etype, count) in rows]


# =========================
#   ADMIN USERS MANAGEMENT
# =========================

@app.get("/admin/users")
def admin_list_users(db: Session = Depends(get_db)):
    rows = db.query(UserAccount).order_by(UserAccount.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "username": r.username,
            "email": r.email,
            "first_name": r.first_name,
            "last_name": r.last_name,
            "company": r.company,
            "is_admin": r.is_admin,
            "is_active": r.is_active,
            "email_verified": r.email_verified,
            "cloud_sync_enabled": r.cloud_sync_enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_login": r.last_login.isoformat() if r.last_login else None,
            "last_sync": r.last_sync.isoformat() if r.last_sync else None,
        }
        for r in rows
    ]

@app.get("/admin/users/{user_id}/licenses")
def admin_get_user_licenses(user_id: int, db: Session = Depends(get_db)):
    user_licenses = db.query(UserLicense).filter(UserLicense.user_id == user_id).all()

    result = []
    for ul in user_licenses:
        activation_count = db.query(Activation).filter(Activation.license_key == ul.license_key).count()

        last_activation = db.query(Activation).filter(
            Activation.license_key == ul.license_key
        ).order_by(Activation.activated_at.desc()).first()

        result.append({
            "license_key": ul.license_key,
            "is_primary": ul.is_primary,
            "assigned_at": ul.assigned_at.isoformat() if ul.assigned_at else None,
            "activation_count": activation_count,
            "cloud_synced": ul.cloud_synced,
            "last_sync": ul.last_sync.isoformat() if ul.last_sync else None,
            "last_activation": {
                "activated_at": last_activation.activated_at.isoformat() if last_activation and last_activation.activated_at else None,
                "fingerprint": last_activation.fingerprint if last_activation else None,
                "app_version": last_activation.app_version if last_activation else None
            } if last_activation else None
        })

    return result

@app.get("/admin/users/stats")
def admin_users_stats(db: Session = Depends(get_db)):
    total_users = db.query(UserAccount).count()
    active_users = db.query(UserAccount).filter(UserAccount.is_active == True).count()
    admin_users = db.query(UserAccount).filter(UserAccount.is_admin == True).count()
    sync_enabled_users = db.query(UserAccount).filter(UserAccount.cloud_sync_enabled == True).count()

    users_with_licenses = db.query(UserLicense.user_id).distinct().count()
    total_licenses_assigned = db.query(UserLicense).count()

    return {
        "total_users": total_users,
        "active_users": active_users,
        "admin_users": admin_users,
        "sync_enabled_users": sync_enabled_users,
        "users_with_licenses": users_with_licenses,
        "total_licenses_assigned": total_licenses_assigned
    }
# =========================
#   main.py  (PART 3/3)
# =========================

BASE_ADMIN_CSS = """
    :root {
        --bg: #020617;
        --bg-elevated: #020617;
        --card: #020617;
        --card-soft: #020617;
        --border-subtle: #1f2937;
        --accent: #3b82f6;
        --accent-soft: #1d4ed8;
        --danger: #ef4444;
        --danger-soft: #4c0519;
        --success: #22c55e;
        --success-soft: #052e16;
        --warning: #eab308;
        --warning-soft: #422006;
        --muted: #9ca3af;
        --text: #e5e7eb;
        --text-soft: #9ca3af;
        --radius: 12px;
    }

    * { box-sizing: border-box; }

    body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: radial-gradient(circle at top left, #1d283a 0, #020617 40%, #000 100%);
        color: var(--text);
        margin: 0;
        padding: 0;
    }

    .topbar {
        position: sticky;
        top: 0;
        z-index: 20;
        backdrop-filter: blur(16px);
        background: linear-gradient(to right, rgba(15,23,42,0.95), rgba(15,23,42,0.9));
        border-bottom: 1px solid var(--border-subtle);
    }

    .topbar-inner {
        max-width: 1200px;
        margin: 0 auto;
        padding: 10px 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .topbar-title { display: flex; align-items: center; gap: 10px; }

    .topbar-logo {
        width: 26px;
        height: 26px;
        border-radius: 8px;
        background: radial-gradient(circle at 30% 0, #38bdf8 0, #6366f1 40%, #000 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 15px;
    }

    .topbar-logo img {
        width: 100%;
        height: 100%;
        object-fit: contain;
        border-radius: 8px;
    }

    .topbar-text-main { font-weight: 600; font-size: 16px; }
    .topbar-text-sub { font-size: 11px; color: var(--muted); }

    .topbar-pills { display: flex; align-items: center; gap: 8px; font-size: 11px; }

    .pill {
        border-radius: 999px;
        padding: 4px 10px;
        border: 1px solid var(--border-subtle);
        background: #020617;
        color: var(--muted);
    }

    .pill-healthy {
        color: #4ade80;
        border-color: #166534;
        background: rgba(22,101,52,0.15);
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 18px 24px 32px 24px;
    }

    h1 { font-size: 28px; margin-bottom: 4px; }
    h2 { margin-top: 32px; margin-bottom: 8px; font-size: 20px; }
    .subtitle { color: var(--muted); margin-bottom: 18px; font-size: 13px; }

    .breadcrumbs { font-size: 12px; margin-bottom: 8px; color: var(--muted); }
    .breadcrumbs a { color: #93c5fd; text-decoration: none; }
    .breadcrumbs a:hover { text-decoration: underline; }

    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 14px;
        margin-bottom: 20px;
    }

    .card {
        background: radial-gradient(circle at top left, rgba(30,64,175,0.2), #020617 55%);
        border-radius: var(--radius);
        padding: 14px 14px 12px 14px;
        border: 1px solid var(--border-subtle);
        box-shadow: 0 18px 40px rgba(0,0,0,0.45);
    }

    .card-muted { background: #020617; }

    .card-title { font-size: 12px; color: var(--muted); }
    .card-value { font-size: 22px; font-weight: 600; margin-top: 4px; }
    .card-extra { font-size: 11px; color: var(--text-soft); margin-top: 2px; }

    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 12px;
        border-radius: var(--radius);
        overflow: hidden;
    }

    thead { position: sticky; top: 52px; z-index: 10; }

    th, td {
        padding: 6px 8px;
        border-bottom: 1px solid #1f2937;
        vertical-align: top;
    }

    th {
        text-align: left;
        background: rgba(15,23,42,0.98);
        font-weight: 600;
        font-size: 11px;
        color: #9ca3af;
    }

    tr:nth-child(even) td { background-color: #020617; }
    tr:nth-child(odd)  td { background-color: #020617; }

    tr.row-warning td { background: rgba(250,204,21,0.04); }
    tr.row-danger td { background: rgba(248,113,113,0.07); }

    .badge {
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        padding: 2px 8px;
        font-size: 11px;
        border: 1px solid transparent;
        gap: 4px;
        white-space: nowrap;
    }

    .badge-green { background-color: rgba(22,163,74,0.2); color: #4ade80; border-color: rgba(22,163,74,0.5); }
    .badge-blue  { background-color: rgba(37,99,235,0.2); color: #93c5fd; border-color: rgba(37,99,235,0.6); }
    .badge-red   { background-color: rgba(220,38,38,0.16); color: #fecaca; border-color: rgba(220,38,38,0.45); }
    .badge-amber { background-color: rgba(234,179,8,0.16); color: #facc15; border-color: rgba(234,179,8,0.45); }
    .badge-muted { background-color: rgba(148,163,184,0.16); color: #e5e7eb; border-color: rgba(148,163,184,0.4); }

    .small { font-size: 11px; color: var(--muted); }

    a { color: #93c5fd; text-decoration: none; }
    a:hover { text-decoration: underline; }

    canvas { max-width: 100%; margin-top: 8px; }

    .pill-actions { margin-top: 4px; font-size: 11px; }
    .pill-actions a { margin-right: 8px; }

    .btn-danger {
        background: linear-gradient(to right, #b91c1c, #ef4444);
        color: #fee2e2;
        border: none;
        border-radius: 999px;
        padding: 8px 16px;
        font-size: 13px;
        cursor: pointer;
        font-weight: 600;
        box-shadow: 0 10px 25px rgba(127,29,29,0.7);
    }
    .btn-danger:hover { background: linear-gradient(to right, #dc2626, #f97373); }

    .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 10px;
    }

    .toolbar-right { display: flex; gap: 8px; align-items: center; }

    .input-search {
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid var(--border-subtle);
        background: #020617;
        color: var(--text);
        font-size: 12px;
        min-width: 180px;
    }
    .input-search::placeholder { color: #6b7280; }

    .tag-filter {
        border-radius: 999px;
        padding: 4px 10px;
        border: 1px solid var(--border-subtle);
        background: #020617;
        color: #9ca3af;
        font-size: 11px;
        cursor: pointer;
    }
    .tag-filter.active {
        border-color: var(--accent);
        background: rgba(37,99,235,0.2);
        color: #bfdbfe;
    }

    .danger-zone-header { display: flex; align-items: center; gap: 8px; color: #fecaca; }

    .network-card { margin-top: 12px; }
    .network-svg-wrapper {
        margin-top: 10px;
        background: #020617;
        border-radius: var(--radius);
        border: 1px solid var(--border-subtle);
        padding: 12px;
    }
    .network-svg-wrapper svg { width: 100%; height: 260px; display: block; }
"""

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(db: Session = Depends(get_db)):
    total_activations = db.query(Activation).count()
    total_machines = db.query(Activation.fingerprint).distinct().count()
    total_revocations = db.query(RevokedLicenseMachine).count()
    total_usage_events = db.query(UsageEvent).count()
    total_licenses = db.query(Activation.license_key).distinct().count()

    total_users = db.query(UserAccount).count()
    active_users = db.query(UserAccount).filter(UserAccount.is_active == True).count()
    sync_enabled_users = db.query(UserAccount).filter(UserAccount.cloud_sync_enabled == True).count()
    total_licenses_assigned = db.query(UserLicense).count()

    distinct_pairs = db.query(Activation.license_key, Activation.fingerprint).distinct().count()
    reactivations = max(total_activations - distinct_pairs, 0)

    last_activations = db.query(Activation).order_by(Activation.created_at.desc()).limit(20).all()
    machines_last = len({a.fingerprint for a in last_activations if a.fingerprint})

    last_usage = db.query(UsageEvent).order_by(UsageEvent.created_at.desc()).limit(50).all()

    stats_by_type = db.query(UsageEvent.event_type, func.count(UsageEvent.id)).group_by(UsageEvent.event_type).all()
    labels = [row[0] for row in stats_by_type]
    counts = [row[1] for row in stats_by_type]

    now = datetime.utcnow()

    deleted_pairs_rows = (
        db.query(UsageEvent.license_key, UsageEvent.fingerprint, func.max(UsageEvent.created_at))
        .filter(UsageEvent.event_type == "LICENSE_DELETED_LOCAL")
        .group_by(UsageEvent.license_key, UsageEvent.fingerprint)
        .all()
    )
    deleted_pairs = {(lk, fp): ts for (lk, fp, ts) in deleted_pairs_rows}

    all_acts = db.query(Activation).order_by(Activation.activated_at.asc()).all()

    first_admin_fp = None
    for a in all_acts:
        if a.fingerprint:
            first_admin_fp = a.fingerprint
            break

    per_fp = defaultdict(list)
    for a in all_acts:
        if a.fingerprint:
            per_fp[a.fingerprint].append(a)

    revoked_rows = db.query(RevokedLicenseMachine).all()
    revoked_pairs_set = {(r.license_key, r.fingerprint) for r in revoked_rows}

    machines_data = []
    for fp, acts in per_fp.items():
        acts_sorted = sorted(acts, key=lambda x: x.activated_at or x.created_at or datetime.min)
        current = acts_sorted[-1]
        lk = current.license_key or ""

        pair_revoked = (lk, fp) in revoked_pairs_set
        is_expired = bool(current.expires_at and current.expires_at < now)

        deleted_at = deleted_pairs.get((lk, fp))
        is_deleted = bool(deleted_at and current.activated_at and deleted_at >= current.activated_at)

        if pair_revoked:
            status = "revoked"
        elif is_deleted:
            status = "deleted"
        elif is_expired:
            status = "expired"
        else:
            status = "active"

        machines_data.append({"fingerprint": fp, "status": status, "is_admin": (fp == first_admin_fp)})

    labels_js = json.dumps(labels)
    counts_js = json.dumps(counts)
    machines_js = json.dumps(machines_data)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Phoenix License Tracker – Admin</title>
  <style>
    {BASE_ADMIN_CSS}
    .tab-container {{
        display: flex;
        gap: 8px;
        margin-bottom: 16px;
        border-bottom: 1px solid var(--border-subtle);
        padding-bottom: 4px;
    }}
    .tab {{
        padding: 8px 16px;
        border-radius: 8px 8px 0 0;
        background: #020617;
        border: 1px solid var(--border-subtle);
        border-bottom: none;
        cursor: pointer;
        font-size: 12px;
        color: var(--muted);
    }}
    .tab.active {{
        background: rgba(37,99,235,0.2);
        border-color: var(--accent);
        color: #bfdbfe;
    }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

<div class="topbar">
  <div class="topbar-inner">
    <div class="topbar-title">
      <div class="topbar-logo">
        <img src="/static/logo.png" alt="Phoenix Logo" style="width:20px;height:20px;border-radius:6px;">
      </div>
      <div>
        <div class="topbar-text-main">Phoenix License Tracker</div>
        <div class="topbar-text-sub">TELNET • PLM Systems • Wisdom® AI</div>
      </div>
    </div>
    <div class="topbar-pills">
      <span class="pill">v{APP_VERSION}</span>
      <span class="pill-healthy">Backend healthy</span>
    </div>
  </div>
</div>

<div class="container">
  <div class="breadcrumbs">Admin · Overview</div>
  <h1>Dashboard</h1>
  <div class="subtitle">
    Centralized overview of all <strong>license activations</strong>, <strong>revocations</strong>, <strong>user accounts</strong> and <strong>usage events</strong> for PHOENIX.
    <br>UTC time: {datetime.utcnow().isoformat().split('.')[0]}Z
  </div>

  <div class="tab-container">
    <div class="tab active" onclick="switchTab('overview')">📊 Overview</div>
    <div class="tab" onclick="switchTab('users')">👥 Users ({total_users})</div>
    <div class="tab" onclick="switchTab('licenses')">🔑 Licenses ({total_licenses})</div>
    <div class="tab" onclick="switchTab('machines')">💻 Machines ({total_machines})</div>
  </div>

  <div id="overview-tab" class="tab-content active">
    <div class="grid">
      <div class="card"><div class="card-title">Total activation events</div><div class="card-value">{total_activations}</div><div class="card-extra">Including first installs and re-activations.</div></div>
      <div class="card"><div class="card-title">Unique machines</div><div class="card-value">{total_machines}</div><div class="card-extra">Distinct hardware fingerprints.</div></div>
      <div class="card"><div class="card-title">Unique licenses</div><div class="card-value">{total_licenses}</div><div class="card-extra">License keys seen at least once.</div></div>
      <div class="card card-muted"><div class="card-title">Re-activations (same license + machine)</div><div class="card-value">{reactivations}</div><div class="card-extra">Potential one-shot violations (auto-revoked).</div></div>
      <div class="card"><div class="card-title">User accounts</div><div class="card-value">{total_users}</div><div class="card-extra">{active_users} active, {sync_enabled_users} with cloud sync</div></div>
      <div class="card card-muted"><div class="card-title">Revoked pairs</div><div class="card-value">{total_revocations}</div><div class="card-extra">license_key + fingerprint marked as revoked.</div></div>
      <div class="card card-muted"><div class="card-title">Usage events</div><div class="card-value">{total_usage_events}</div><div class="card-extra">APP_OPEN, MODULE_OPEN, LICENSE_EXPIRED_LOCAL, ...</div></div>
      <div class="card"><div class="card-title">Licenses assigned</div><div class="card-value">{total_licenses_assigned}</div><div class="card-extra">Licenses linked to user accounts</div></div>
    </div>

    <h2>Réseau des licences PHOENIX</h2>
    <div class="card network-card">
      <div class="small">
        Ici, la <strong>première machine activée</strong> est considérée comme le <strong>PC Admin</strong>.
        Chaque nouvelle activation ajoute un <strong>PC client</strong> connecté à ce noyau.
      </div>
      <div id="networkContainer" class="network-svg-wrapper">
        <svg id="networkSvg" viewBox="0 0 600 260"></svg>
      </div>
      <div class="small" style="margin-top:6px;">Cliquez sur un nœud 💻 pour ouvrir le détail de la machine (fingerprint).</div>
    </div>

    <h2>Usage by event type</h2>
    <div class="card">
      <div class="small">Distribution of all usage events</div>
      <canvas id="usageChart" height="120"></canvas>
    </div>

    <h2>Last activations</h2>
    <div class="small" style="margin-bottom:6px;">{machines_last} machines • {len(last_activations)} activation events.</div>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>License key</th><th>Fingerprint</th><th>Status</th><th>User</th><th>Activated at</th><th>Expires at</th>
          </tr>
        </thead>
        <tbody>
    """

    for r in last_activations:
        user_name = ((r.user_first_name or "") + " " + (r.user_last_name or "")).strip() or "—"
        act = r.activated_at.isoformat() if r.activated_at else ""
        exp = r.expires_at.isoformat() if r.expires_at else ""

        pair_revoked = db.query(RevokedLicenseMachine).filter(
            RevokedLicenseMachine.license_key == r.license_key,
            RevokedLicenseMachine.fingerprint == r.fingerprint,
        ).first() is not None

        is_expired = bool(r.expires_at and r.expires_at < datetime.utcnow())

        latest_for_machine = db.query(Activation).filter(
            Activation.fingerprint == r.fingerprint
        ).order_by(Activation.activated_at.desc()).first()
        is_latest_for_machine = bool(latest_for_machine and latest_for_machine.id == r.id)

        pair_key = (r.license_key, r.fingerprint)
        deleted_at = deleted_pairs.get(pair_key)
        is_deleted_local = bool(deleted_at and r.activated_at and deleted_at >= r.activated_at)

        if pair_revoked:
            status_badge = '<span class="badge badge-red">Revoked</span>'
            row_class = "row-danger"
        elif is_expired:
            status_badge = '<span class="badge badge-red">Expired</span>'
            row_class = "row-danger"
        elif is_deleted_local:
            status_badge = '<span class="badge badge-amber">Deleted locally</span>'
            row_class = "row-warning"
        elif is_latest_for_machine:
            status_badge = '<span class="badge badge-green">Active</span>'
            row_class = ""
        else:
            status_badge = '<span class="badge badge-muted">Inactive</span>'
            row_class = ""

        pair_count_before = db.query(Activation).filter(
            Activation.license_key == r.license_key,
            Activation.fingerprint == r.fingerprint,
            Activation.activated_at <= r.activated_at,
        ).count()

        status_info = "First activation on this machine" if pair_count_before <= 1 else f"Reactivation #{pair_count_before} on this machine"
        if is_deleted_local:
            status_info += " (deleted locally on client)"

        safe_lk = quote(r.license_key or "", safe="")
        safe_fp = quote(r.fingerprint or "", safe="")

        revoke_link = f"/revoke?license_key={safe_lk}&fingerprint={safe_fp}"
        unrevoke_link = f"/unrevoke?license_key={safe_lk}&fingerprint={safe_fp}"

        html += f"""
          <tr class="{row_class}">
            <td>{r.id}</td>
            <td><a href="/admin/license/{safe_lk}" class="badge badge-blue">{r.license_key}</a></td>
            <td><a href="/admin/machine/{safe_fp}" class="badge badge-green">{r.fingerprint}</a></td>
            <td>
              {status_badge}
              <div class="small">{status_info}</div>
              <div class="pill-actions"><a href="{revoke_link}">Revoke</a>· <a href="{unrevoke_link}">Unrevoke</a></div>
            </td>
            <td>{user_name}</td>
            <td>{act}</td>
            <td>{exp}</td>
          </tr>
        """

    html += """
        </tbody>
      </table>
      <div class="small">Full JSON: <a href="/admin/activations" target="_blank">/admin/activations</a></div>
    </div>

    <h2>Last usage events</h2>
    <div class="toolbar">
      <div class="small">Monitor live activity from PHOENIX.</div>
      <div class="toolbar-right">
        <input id="usageSearch" class="input-search" placeholder="Filter by license, fingerprint or details…" />
        <button class="tag-filter active" data-filter="ALL">All</button>
        <button class="tag-filter" data-filter="LICENSE_">License</button>
        <button class="tag-filter" data-filter="APP_OPEN">APP_OPEN</button>
        <button class="tag-filter" data-filter="CHATBOT_CALL">CHATBOT</button>
      </div>
    </div>

    <div class="card">
      <table id="usageTable">
        <thead>
          <tr>
            <th>ID</th><th>Type</th><th>Source</th><th>License key</th><th>Fingerprint</th><th>Created at</th><th>Details</th>
          </tr>
        </thead>
        <tbody>
    """

    for u in last_usage:
        created = u.created_at.isoformat() if u.created_at else ""
        details = (u.details or "")[:80] + ("..." if len(u.details or "") > 80 else "")
        safe_lk = quote(u.license_key or "", safe="")
        safe_fp = quote(u.fingerprint or "", safe="")

        if (u.event_type or "").startswith("LICENSE_EXPIRED") or (u.event_type or "").startswith("LICENSE_DELETED"):
            badge_class = "badge-amber"
            row_class = "row-warning"
        elif (u.event_type or "").startswith("LICENSE_REVOKED"):
            badge_class = "badge-red"
            row_class = "row-danger"
        elif u.event_type == "APP_OPEN":
            badge_class = "badge-green"
            row_class = ""
        else:
            badge_class = "badge-blue"
            row_class = ""

        html += f"""
          <tr class="{row_class}" data-type="{u.event_type}">
            <td>{u.id}</td>
            <td><span class="badge {badge_class}">{u.event_type}</span></td>
            <td>{u.event_source}</td>
            <td class="small"><a href="/admin/license/{safe_lk}" target="_blank">{u.license_key}</a></td>
            <td class="small"><a href="/admin/machine/{safe_fp}" target="_blank">{u.fingerprint}</a></td>
            <td>{created}</td>
            <td class="small">{details}</td>
          </tr>
        """

    html += f"""
        </tbody>
      </table>
      <div class="small">Full JSON: <a href="/admin/usage/recent" target="_blank">/admin/usage/recent</a></div>
    </div>
  </div>

  <div id="users-tab" class="tab-content">
    <h2>User Accounts Management</h2>
    <div class="card">
      <div class="toolbar">
        <div class="small">Total users: {total_users} • Active: {active_users} • Cloud sync enabled: {sync_enabled_users}</div>
        <div class="toolbar-right"><input id="userSearch" class="input-search" placeholder="Search users..." /></div>
      </div>
      <table id="usersTable">
        <thead>
          <tr><th>ID</th><th>Username</th><th>Email</th><th>Name</th><th>Company</th><th>Status</th><th>Created</th><th>Last Login</th><th>Actions</th></tr>
        </thead>
        <tbody>
    """

    all_users = db.query(UserAccount).order_by(UserAccount.created_at.desc()).all()
    for user in all_users:
        status_badges = []
        if user.is_admin:
            status_badges.append('<span class="badge badge-blue">Admin</span>')
        if not user.is_active:
            status_badges.append('<span class="badge badge-red">Inactive</span>')
        if user.cloud_sync_enabled:
            status_badges.append('<span class="badge badge-green">Cloud Sync</span>')
        status_badges.append('<span class="badge badge-green">Verified</span>' if user.email_verified else '<span class="badge badge-amber">Unverified</span>')

        status_html = " ".join(status_badges)
        license_count = db.query(UserLicense).filter(UserLicense.user_id == user.id).count()

        html += f"""
          <tr>
            <td>{user.id}</td>
            <td><strong>{user.username}</strong><div class="small">Licenses: {license_count}</div></td>
            <td>{user.email}</td>
            <td>{user.first_name or ''} {user.last_name or ''}</td>
            <td>{user.company or '—'}</td>
            <td>{status_html}</td>
            <td>{user.created_at.isoformat() if user.created_at else '—'}</td>
            <td>{user.last_login.isoformat() if user.last_login else 'Never'}</td>
            <td><div class="pill-actions"><a href="/admin/users/{user.id}/licenses" target="_blank">View Licenses</a></div></td>
          </tr>
        """

    html += """
        </tbody>
      </table>
      <div class="small">
        Full JSON: <a href="/admin/users" target="_blank">/admin/users</a> •
        Stats: <a href="/admin/users/stats" target="_blank">/admin/users/stats</a>
      </div>
    </div>
  </div>

  <div id="licenses-tab" class="tab-content">
    <h2>License Management</h2>
    <div class="card">
      <div class="toolbar">
        <div class="small">Total licenses: """ + str(total_licenses) + """ • Assigned to users: """ + str(total_licenses_assigned) + """</div>
        <div class="toolbar-right"><input id="licenseSearch" class="input-search" placeholder="Search licenses..." /></div>
      </div>
      <table id="licensesTable">
        <thead>
          <tr><th>License Key</th><th>Activations</th><th>Machines</th><th>Assigned Users</th><th>First Activation</th><th>Last Activation</th><th>Status</th></tr>
        </thead>
        <tbody>
    """

    licenses_data = admin_list_licenses(db)
    for license_data in licenses_data[:50]:
        license_key = license_data["license_key"]

        assigned_users = db.query(UserLicense).filter(UserLicense.license_key == license_key).all()
        user_names = []
        for ul in assigned_users:
            u = db.query(UserAccount).filter(UserAccount.id == ul.user_id).first()
            if u:
                user_names.append(u.username)

        has_active = False
        has_revoked = False
        has_expired = False

        activations = db.query(Activation).filter(Activation.license_key == license_key).all()
        for act in activations:
            if act.expires_at and act.expires_at < now:
                has_expired = True
            else:
                has_active = True
            revoked = db.query(RevokedLicenseMachine).filter(
                RevokedLicenseMachine.license_key == license_key,
                RevokedLicenseMachine.fingerprint == act.fingerprint
            ).first()
            if revoked:
                has_revoked = True

        status_badges = []
        if has_active:
            status_badges.append('<span class="badge badge-green">Active</span>')
        if has_revoked:
            status_badges.append('<span class="badge badge-red">Revoked</span>')
        if has_expired:
            status_badges.append('<span class="badge badge-amber">Expired</span>')

        status_html = " ".join(status_badges)
        safe_lk = quote(license_key or "", safe="")

        html += f"""
          <tr>
            <td><a href="/admin/license/{safe_lk}" class="badge badge-blue">{license_key[:30]}{'...' if len(license_key) > 30 else ''}</a></td>
            <td>{license_data['total_activations']}</td>
            <td>{license_data['unique_machines']}</td>
            <td>{', '.join(user_names[:2])}{'...' if len(user_names) > 2 else '' if user_names else '—'}<div class="small">Total: {len(user_names)} users</div></td>
            <td>{license_data['first_activation_at'] or '—'}</td>
            <td>{license_data['last_activation_at'] or '—'}</td>
            <td>{status_html}</td>
          </tr>
        """

    html += """
        </tbody>
      </table>
      <div class="small">Full JSON: <a href="/admin/licenses" target="_blank">/admin/licenses</a></div>
    </div>
  </div>

  <div id="machines-tab" class="tab-content">
    <h2>Machines Management</h2>
    <div class="card">
      <div class="toolbar">
        <div class="small">Total machines: """ + str(total_machines) + """</div>
        <div class="toolbar-right"><input id="machineSearch" class="input-search" placeholder="Search machines..." /></div>
      </div>
      <table id="machinesTable">
        <thead>
          <tr><th>Fingerprint</th><th>Activations</th><th>Licenses</th><th>First Activation</th><th>Last Activation</th><th>Status</th></tr>
        </thead>
        <tbody>
    """

    machines_data_admin = admin_list_machines(db)
    for machine_data in machines_data_admin[:50]:
        fingerprint = machine_data["fingerprint"]

        has_active = False
        has_revoked = False
        has_expired = False

        activations = db.query(Activation).filter(Activation.fingerprint == fingerprint).all()
        for act in activations:
            if act.expires_at and act.expires_at < now:
                has_expired = True
            else:
                has_active = True
            revoked = db.query(RevokedLicenseMachine).filter(
                RevokedLicenseMachine.license_key == act.license_key,
                RevokedLicenseMachine.fingerprint == fingerprint
            ).first()
            if revoked:
                has_revoked = True

        status_badges = []
        if has_active:
            status_badges.append('<span class="badge badge-green">Active</span>')
        if has_revoked:
            status_badges.append('<span class="badge badge-red">Revoked</span>')
        if has_expired:
            status_badges.append('<span class="badge badge-amber">Expired</span>')

        status_html = " ".join(status_badges)
        safe_fp = quote(fingerprint or "", safe="")

        html += f"""
          <tr>
            <td><a href="/admin/machine/{safe_fp}" class="badge badge-green">{fingerprint[:30]}{'...' if len(fingerprint) > 30 else ''}</a></td>
            <td>{machine_data['total_activations']}</td>
            <td>{', '.join(machine_data['licenses'][:2])}{'...' if len(machine_data['licenses']) > 2 else ''}<div class="small">Total: {len(machine_data['licenses'])} licenses</div></td>
            <td>{machine_data['first_activation_at'] or '—'}</td>
            <td>{machine_data['last_activation_at'] or '—'}</td>
            <td>{status_html}</td>
          </tr>
        """

    html += """
        </tbody>
      </table>
      <div class="small">Full JSON: <a href="/admin/machines" target="_blank">/admin/machines</a></div>
    </div>
  </div>

  <h2>Raw Admin APIs</h2>
  <div class="card card-muted">
    <div class="small">
      <ul>
        <li><a href="/admin/activations" target="_blank">/admin/activations</a></li>
        <li><a href="/admin/licenses" target="_blank">/admin/licenses</a></li>
        <li><a href="/admin/machines" target="_blank">/admin/machines</a></li>
        <li><a href="/admin/revocations" target="_blank">/admin/revocations</a></li>
        <li><a href="/admin/usage/recent" target="_blank">/admin/usage/recent</a></li>
        <li><a href="/admin/usage/stats/by-type" target="_blank">/admin/usage/stats/by-type</a></li>
        <li><a href="/admin/users" target="_blank">/admin/users</a></li>
        <li><a href="/admin/users/stats" target="_blank">/admin/users/stats</a></li>
      </ul>
    </div>
  </div>

  <h2 style="color:#fca5a5;" class="danger-zone-header">Danger zone</h2>
  <div class="card card-muted">
    <div class="small" style="margin-bottom:8px;">
      ⚠ This will <strong>delete ALL activations, usage logs, revocations, users</strong> from the database.
    </div>
    <form onsubmit="return confirmDelete(event)">
      <input id="adminPassword" type="password" placeholder="Admin password"
             style="padding:6px;border-radius:6px;width:220px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;">
      <button type="submit" class="btn-danger" style="margin-left:8px;">Delete ALL data</button>
    </form>
    <div id="deleteResult" class="small" style="margin-top:6px;"></div>
  </div>

</div>

<script>
  const labels = {labels_js};
  const dataCounts = {counts_js};
  const machinesData = {machines_js};

  const ctx = document.getElementById('usageChart').getContext('2d');
  new Chart(ctx, {{
    type: 'bar',
    data: {{ labels: labels, datasets: [{{ label: 'Events count', data: dataCounts }}] }},
    options: {{
      plugins: {{ legend: {{ labels: {{ color: '#e5e7eb' }} }} }},
      scales: {{
        x: {{ ticks: {{ color: '#9ca3af' }}, grid: {{ color: '#1f2937' }} }},
        y: {{ ticks: {{ color: '#9ca3af' }}, grid: {{ color: '#1f2937' }} }}
      }}
    }}
  }});

  function drawNetworkDiagram(machines) {{
    const svg = document.getElementById('networkSvg');
    if (!svg || !machines || machines.length === 0) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    const adminX = 450;
    const adminY = 130;

    const admin = machines.find(m => m.is_admin) || null;
    const clients = machines.filter(m => !m.is_admin);

    function statusColor(status) {{
      if (status === "active") return "#22c55e";
      return "#ef4444";
    }}

    const n = clients.length;
    const clientPositions = [];
    if (n > 0) {{
      const top = 50;
      const bottom = 210;
      const step = (bottom - top) / (n + 1);
      clients.forEach((m, idx) => {{
        const y = top + step * (idx + 1);
        clientPositions.push({{ ...m, x: 150, y }});
      }});
    }}

    clientPositions.forEach(pos => {{
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", pos.x);
      line.setAttribute("y1", pos.y);
      line.setAttribute("x2", adminX);
      line.setAttribute("y2", adminY);
      line.setAttribute("stroke", statusColor(pos.status));
      line.setAttribute("stroke-width", "3");
      svg.appendChild(line);
    }});

    if (admin) {{
      const adminNode = document.createElementNS("http://www.w3.org/2000/svg", "a");
      adminNode.setAttribute("href", "/admin/machine/" + encodeURIComponent(admin.fingerprint));

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", adminX);
      circle.setAttribute("cy", adminY);
      circle.setAttribute("r", "30");
      circle.setAttribute("fill", statusColor(admin.status));
      circle.setAttribute("stroke", "#0f172a");
      circle.setAttribute("stroke-width", "3");
      adminNode.appendChild(circle);

      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", adminX);
      text.setAttribute("y", adminY + 5);
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("font-size", "14");
      text.setAttribute("fill", "#020617");
      text.textContent = "🖥 ADMIN";
      adminNode.appendChild(text);

      svg.appendChild(adminNode);
    }}

    clientPositions.forEach(pos => {{
      const node = document.createElementNS("http://www.w3.org/2000/svg", "a");
      node.setAttribute("href", "/admin/machine/" + encodeURIComponent(pos.fingerprint));

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", pos.x);
      circle.setAttribute("cy", pos.y);
      circle.setAttribute("r", "22");
      circle.setAttribute("fill", statusColor(pos.status));
      circle.setAttribute("stroke", "#0f172a");
      circle.setAttribute("stroke-width", "3");
      node.appendChild(circle);

      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", pos.x);
      text.setAttribute("y", pos.y + 5);
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("font-size", "14");
      text.setAttribute("fill", "#020617");
      text.textContent = "💻";
      node.appendChild(text);

      svg.appendChild(node);
    }});
  }}

  drawNetworkDiagram(machinesData);

  function switchTab(tabName) {{
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById(tabName + '-tab').classList.add('active');
    if (tabName === 'overview') drawNetworkDiagram(machinesData);
  }}

  function setupSearch(tableId, searchId) {{
    const searchInput = document.getElementById(searchId);
    const table = document.getElementById(tableId);
    if (searchInput && table) {{
      searchInput.addEventListener('input', function() {{
        const filter = this.value.toLowerCase();
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {{
          const text = row.innerText.toLowerCase();
          row.style.display = text.includes(filter) ? '' : 'none';
        }});
      }});
    }}
  }}

  setupSearch('usersTable', 'userSearch');
  setupSearch('licensesTable', 'licenseSearch');
  setupSearch('machinesTable', 'machineSearch');

  const usageSearch = document.getElementById('usageSearch');
  const usageTable = document.getElementById('usageTable');
  const filterButtons = document.querySelectorAll('.tag-filter');

  function applyFilters() {{
    if (!usageTable) return;
    const rows = usageTable.querySelectorAll('tbody tr');
    const query = (usageSearch ? usageSearch.value.toLowerCase() : "").trim();
    const activeFilterBtn = document.querySelector('.tag-filter.active');
    const filterType = activeFilterBtn ? activeFilterBtn.getAttribute('data-filter') : 'ALL';

    rows.forEach(row => {{
      const type = row.getAttribute('data-type') || "";
      const text = row.innerText.toLowerCase();

      let matchType = true;
      if (filterType !== 'ALL') {{
        if (filterType === 'LICENSE_') matchType = type.startsWith('LICENSE_');
        else matchType = type.indexOf(filterType) !== -1;
      }}

      let matchText = !query || text.indexOf(query) !== -1;
      row.style.display = (matchType && matchText) ? '' : 'none';
    }});
  }}

  if (usageSearch) usageSearch.addEventListener('input', applyFilters);
  filterButtons.forEach(btn => {{
    btn.addEventListener('click', () => {{
      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      applyFilters();
    }});
  }});
  applyFilters();

  async function confirmDelete(e) {{
    e.preventDefault();
    const passInput = document.getElementById('adminPassword');
    const result = document.getElementById('deleteResult');
    const password = (passInput.value || "").trim();
    if (!password) {{ alert("Please enter the admin password."); return false; }}

    if (!confirm("⚠️ This will DELETE ALL DATA. Continue?")) return false;

    try {{
      const resp = await fetch("/admin/confirm-delete?password=" + encodeURIComponent(password), {{ method: "POST" }});
      const data = await resp.json();
      if (!resp.ok) {{
        result.style.color = "#fca5a5";
        result.textContent = "❌ Error: " + (data.detail || resp.status);
        return false;
      }}
      result.style.color = "#4ade80";
      result.textContent = "✅ Database wiped successfully.";
      setTimeout(() => window.location.reload(), 1500);
    }} catch (err) {{
      alert("Network error: " + err);
    }}
    return false;
  }}
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

    revoked_rows = (
        db.query(RevokedLicenseMachine)
        .filter(RevokedLicenseMachine.fingerprint == fingerprint)
        .all()
    )

    revoked_license_keys = {r.license_key for r in revoked_rows}

    deleted_rows = (
        db.query(UsageEvent.license_key, func.max(UsageEvent.created_at))
        .filter(
            UsageEvent.fingerprint == fingerprint,
            UsageEvent.event_type == "LICENSE_DELETED_LOCAL",
        )
        .group_by(UsageEvent.license_key)
        .all()
    )
    deleted_by_license = {lk: ts for (lk, ts) in deleted_rows}

    total_activations = len(activations)
    licenses = sorted({a.license_key for a in activations if a.license_key})
    first_act = activations[0].activated_at.isoformat() if activations and activations[0].activated_at else "—"
    last_act = activations[-1].activated_at.isoformat() if activations and activations[-1].activated_at else "—"

    now = datetime.utcnow()
    current_activation = activations[-1] if activations else None

    last_activation_for_license = {}
    for a in activations:
        if not a.license_key:
            continue
        prev = last_activation_for_license.get(a.license_key)
        if prev is None or (a.activated_at and a.activated_at > prev.activated_at):
            last_activation_for_license[a.license_key] = a

    if not current_activation:
        machine_status_badge = '<span class="badge badge-blue">No activations</span>'
    else:
        current_revoked = db.query(RevokedLicenseMachine).filter(
            RevokedLicenseMachine.license_key == current_activation.license_key,
            RevokedLicenseMachine.fingerprint == current_activation.fingerprint,
        ).first() is not None

        current_expired = bool(current_activation.expires_at and current_activation.expires_at < now)

        deleted_at_current = deleted_by_license.get(current_activation.license_key)
        is_deleted_current = bool(
            deleted_at_current and current_activation.activated_at and deleted_at_current >= current_activation.activated_at
        )

        if current_revoked:
            machine_status_badge = '<span class="badge badge-red">Current license revoked</span>'
        elif is_deleted_current:
            machine_status_badge = '<span class="badge badge-red">Current license deleted locally</span>'
        elif current_expired:
            machine_status_badge = '<span class="badge badge-red">Current license expired</span>'
        else:
            machine_status_badge = '<span class="badge badge-green">Current license active</span>'

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Machine {fingerprint} – Phoenix Admin</title><style>{BASE_ADMIN_CSS}</style></head>
<body>
<div class="container">
  <div class="breadcrumbs"><a href="/admin">Admin</a> · Machine</div>
  <h1>Machine details</h1>
  <div class="subtitle">
    Fingerprint: <span class="badge badge-green">{fingerprint}</span> &nbsp; {machine_status_badge}
  </div>

  <div class="grid">
    <div class="card"><div class="card-title">Total activations</div><div class="card-value">{total_activations}</div></div>
    <div class="card"><div class="card-title">Licenses used</div><div class="card-value">{len(licenses)}</div></div>
    <div class="card"><div class="card-title">First activation</div><div class="card-value" style="font-size:13px;">{first_act}</div></div>
    <div class="card"><div class="card-title">Last activation</div><div class="card-value" style="font-size:13px;">{last_act}</div></div>
  </div>

  <h2>Licenses on this machine</h2>
  <div class="card"><ul class="small">
    """

    if licenses:
        current_license_key = current_activation.license_key if current_activation else None
        current_revoked_flag = bool(current_activation and current_activation.license_key in revoked_license_keys)
        current_expired_flag = bool(current_activation and current_activation.expires_at and current_activation.expires_at < now)

        for lk in licenses:
            safe_lk = quote(lk or "", safe="")
            safe_fp = quote(fingerprint or "", safe="")

            last_act_for_lk = last_activation_for_license.get(lk)
            deleted_at = deleted_by_license.get(lk)
            is_deleted = bool(deleted_at and last_act_for_lk and last_act_for_lk.activated_at and deleted_at >= last_act_for_lk.activated_at)

            if lk == current_license_key:
                if current_revoked_flag:
                    badge = '<span class="badge badge-red">Revoked (current)</span>'
                elif is_deleted:
                    badge = '<span class="badge badge-red">Deleted locally (current)</span>'
                elif current_expired_flag:
                    badge = '<span class="badge badge-red">Expired (current)</span>'
                else:
                    badge = '<span class="badge badge-green">Active (current)</span>'
            else:
                if lk in revoked_license_keys:
                    badge = '<span class="badge badge-red">Revoked</span>'
                elif is_deleted:
                    badge = '<span class="badge badge-red">Deleted locally</span>'
                else:
                    badge = '<span class="badge badge-red">Inactive</span>'

            revoke_link = f"/revoke?license_key={safe_lk}&fingerprint={safe_fp}"
            unrevoke_link = f"/unrevoke?license_key={safe_lk}&fingerprint={safe_fp}"
            html += f"""
      <li>
        <a href="/admin/license/{safe_lk}">{lk}</a> &nbsp; {badge}
        <span class="pill-actions"><a href="{revoke_link}">Revoke</a>· <a href="{unrevoke_link}">Unrevoke</a></span>
      </li>
            """
    else:
        html += "<li>No license recorded yet.</li>"

    html += """
  </ul></div>

  <h2>Usage events on this machine</h2>
  <div class="card">
    <table>
      <thead><tr><th>ID</th><th>Type</th><th>Source</th><th>License key</th><th>Created at</th><th>Details</th></tr></thead>
      <tbody>
    """

    for u in usage:
        created = u.created_at.isoformat() if u.created_at else ""
        details = (u.details or "")[:80] + ("..." if len(u.details or "") > 80 else "")
        safe_lk = quote(u.license_key or "", safe="")
        html += f"""
        <tr>
          <td>{u.id}</td>
          <td><span class="badge badge-blue">{u.event_type}</span></td>
          <td>{u.event_source}</td>
          <td class="small"><a href="/admin/license/{safe_lk}">{u.license_key}</a></td>
          <td>{created}</td>
          <td class="small">{details}</td>
        </tr>
        """

    html += """
      </tbody>
    </table>
  </div>
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
    revoked_fingerprints = {r.fingerprint for r in revoked_pairs}

    deleted_rows = (
        db.query(UsageEvent.fingerprint, func.max(UsageEvent.created_at))
        .filter(
            UsageEvent.license_key == license_key,
            UsageEvent.event_type == "LICENSE_DELETED_LOCAL",
        )
        .group_by(UsageEvent.fingerprint)
        .all()
    )
    deleted_by_fp = {fp: ts for (fp, ts) in deleted_rows}

    total_activations = len(activations)
    machines = sorted({a.fingerprint for a in activations if a.fingerprint})
    first_act = activations[0].activated_at.isoformat() if activations and activations[0].activated_at else "—"
    last_act = activations[-1].activated_at.isoformat() if activations and activations[-1].activated_at else "—"
    now = datetime.utcnow()

    last_global_for_fp = {}
    for fp in machines:
        last_global_for_fp[fp] = (
            db.query(Activation)
            .filter(Activation.fingerprint == fp)
            .order_by(Activation.activated_at.desc())
            .first()
        )

    last_activation_for_fp = {}
    for a in activations:
        if not a.fingerprint:
            continue
        prev = last_activation_for_fp.get(a.fingerprint)
        if prev is None or (a.activated_at and a.activated_at > prev.activated_at):
            last_activation_for_fp[a.fingerprint] = a

    pair_status_by_fp = {}
    for fp in machines:
        latest = last_global_for_fp.get(fp)
        latest_for_license = last_activation_for_fp.get(fp)
        pair_revoked = fp in revoked_fingerprints

        deleted_at = deleted_by_fp.get(fp)
        is_deleted = bool(deleted_at and latest_for_license and latest_for_license.activated_at and deleted_at >= latest_for_license.activated_at)

        if not latest or latest.license_key != license_key:
            if pair_revoked:
                pair_status_by_fp[fp] = "revoked"
            elif is_deleted:
                pair_status_by_fp[fp] = "deleted"
            else:
                pair_status_by_fp[fp] = "inactive"
        else:
            is_expired = bool(latest.expires_at and latest.expires_at < now)
            if pair_revoked:
                pair_status_by_fp[fp] = "revoked"
            elif is_deleted:
                pair_status_by_fp[fp] = "deleted"
            elif is_expired:
                pair_status_by_fp[fp] = "expired"
            else:
                pair_status_by_fp[fp] = "active"

    active_machine_count = len([fp for fp, st in pair_status_by_fp.items() if st == "active"])
    revoked_machine_count = len(revoked_fingerprints)
    deleted_machine_count = len([fp for fp, st in pair_status_by_fp.items() if st == "deleted"])

    if active_machine_count > 0:
        license_status_badge = f'<span class="badge badge-green">Active on {active_machine_count} machine(s)</span>'
    elif deleted_machine_count > 0:
        license_status_badge = f'<span class="badge badge-red">Deleted locally on {deleted_machine_count} machine(s)</span>'
    elif revoked_machine_count > 0:
        license_status_badge = f'<span class="badge badge-red">No active machines ({revoked_machine_count} revoked)</span>'
    else:
        license_status_badge = '<span class="badge badge-red">No active machines</span>'

    safe_lk_global = quote(license_key or "", safe="")

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>License {license_key} – Phoenix Admin</title><style>{BASE_ADMIN_CSS}</style></head>
<body>
<div class="container">
  <div class="breadcrumbs"><a href="/admin">Admin</a> · License</div>
  <h1>License details</h1>
  <div class="subtitle">License key: <span class="badge badge-blue">{license_key}</span> &nbsp; {license_status_badge}</div>

  <div class="grid">
    <div class="card"><div class="card-title">Total activations</div><div class="card-value">{total_activations}</div></div>
    <div class="card"><div class="card-title">Unique machines</div><div class="card-value">{len(machines)}</div></div>
    <div class="card"><div class="card-title">Active machines</div><div class="card-value">{active_machine_count}</div></div>
    <div class="card"><div class="card-title">Revoked machines</div><div class="card-value">{revoked_machine_count}</div></div>
    <div class="card"><div class="card-title">First activation</div><div class="card-value" style="font-size:13px;">{first_act}</div></div>
    <div class="card"><div class="card-title">Last activation</div><div class="card-value" style="font-size:13px;">{last_act}</div></div>
  </div>

  <h2>Machines using this license</h2>
  <div class="card"><ul class="small">
    """

    if machines:
        for fp in machines:
            safe_fp = quote(fp or "", safe="")
            status = pair_status_by_fp.get(fp, "inactive")
            if status == "active":
                badge = '<span class="badge badge-green">Active</span>'
            elif status == "revoked":
                badge = '<span class="badge badge-red">Revoked</span>'
            elif status == "expired":
                badge = '<span class="badge badge-red">Expired</span>'
            elif status == "deleted":
                badge = '<span class="badge badge-red">Deleted locally</span>'
            else:
                badge = '<span class="badge badge-red">Inactive</span>'

            revoke_link = f"/revoke?license_key={safe_lk_global}&fingerprint={safe_fp}"
            unrevoke_link = f"/unrevoke?license_key={safe_lk_global}&fingerprint={safe_fp}"
            html += f"""
      <li>
        <a href="/admin/machine/{safe_fp}">{fp}</a> &nbsp; {badge}
        <span class="pill-actions"><a href="{revoke_link}">Revoke</a>· <a href="{unrevoke_link}">Unrevoke</a></span>
      </li>
            """
    else:
        html += "<li>No machine recorded yet.</li>"

    html += """
  </ul></div>

  <h2>Usage events for this license</h2>
  <div class="card">
    <table>
      <thead><tr><th>ID</th><th>Type</th><th>Source</th><th>Fingerprint</th><th>Created at</th><th>Details</th></tr></thead>
      <tbody>
    """

    for u in usage:
        created = u.created_at.isoformat() if u.created_at else ""
        details = (u.details or "")[:80] + ("..." if len(u.details or "") > 80 else "")
        safe_fp = quote(u.fingerprint or "", safe="")
        html += f"""
        <tr>
          <td>{u.id}</td>
          <td><span class="badge badge-blue">{u.event_type}</span></td>
          <td>{u.event_source}</td>
          <td class="small"><a href="/admin/machine/{safe_fp}">{u.fingerprint}</a></td>
          <td>{created}</td>
          <td class="small">{details}</td>
        </tr>
        """

    html += """
      </tbody>
    </table>
  </div>
</div>
</body>
</html>
"""
    return HTMLResponse(content=html)
