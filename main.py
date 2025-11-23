import os
from datetime import datetime
from typing import Optional
from collections import defaultdict

import requests
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# =========================
#   CONFIG
# =========================

# BDD : Render fournit DATABASE_URL (Postgres).
# En local, on utilise SQLite par défaut.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./activations.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Telegram (penser à définir ces variables dans Render)
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
    Option B (plus strict) :
    Révocation par PAIRE (license_key + fingerprint).
    - On peut révoquer une licence sur un PC volé
    - Mais la même licence peut continuer ailleurs si tu veux.
    """
    __tablename__ = "revoked_license_machines"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, index=True)
    fingerprint = Column(String, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)


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
    allow_origins=["*"],   # tu peux restreindre si tu veux
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
    total_activations: int              # toutes machines confondues
    machine_activations: int            # nombre d’activations pour CE PC
    is_first_activation_for_machine: bool


# =========================
#   Telegram helper
# =========================

def send_telegram_message(text: str) -> None:
    """Envoie un message Telegram si le bot est configuré."""
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
    """Simple healthcheck pour Render / Uptime etc."""
    return {"status": "ok", "version": APP_VERSION}


@app.post("/activation", response_model=ActivationOut)
def register_activation(data: ActivationIn, db: Session = Depends(get_db)):
    """
    Enregistre UNE activation supplémentaire.

    ⚠️ IMPORTANT :
    - On ajoute toujours une nouvelle ligne (on ne supprime jamais).
    - Donc on garde l'historique complet de toutes les activations.
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

    # total global
    total = db.query(Activation).count()

    # activations pour CE fingerprint
    machine_count = (
        db.query(Activation)
        .filter(Activation.fingerprint == data.fingerprint)
        .count()
    )
    is_first_for_machine = machine_count == 1

    # Telegram
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
    """Stat global : nombre TOTAL d'activations (toutes machines)."""
    total = db.query(Activation).count()
    return {"total_activations": total}


@app.get("/stats/machine/{fingerprint}")
def stats_machine(fingerprint: str, db: Session = Depends(get_db)):
    """Stat pour une machine donnée (même PC = même fingerprint)."""
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
    """
    Révoque une PAIRE (license_key + fingerprint).
    -> Utile si un client dit "mon PC est volé".
    -> Cette licence ne fonctionnera plus sur CE PC précis.

    Accessible en :
    - POST (script, API)
    - GET (simple clic navigateur)
    """

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

        # Telegram notif
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


@app.get("/license/status/{license_key}/{fingerprint}")
def license_status(license_key: str, fingerprint: str, db: Session = Depends(get_db)):
    """
    Permet au CLIENT de savoir si (license_key, fingerprint) est révoqué.
    Utilisé au démarrage de l'app.
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


# =========================
#   ROUTES ADMIN (Tableau sans UI)
# =========================

@app.get("/admin/activations")
def admin_list_activations(db: Session = Depends(get_db)):
    """
    Liste TOUTES les activations, pour ton dashboard admin.
    """
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
    """
    Vue agrégée par license_key :
    - total_activations
    - unique_machines
    - first_activation_at
    - last_activation_at
    """
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
    """
    Liste toutes les machines révoquées (license_key + fingerprint).
    """
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
    """
    Vue par MACHINE (fingerprint) :
    - quelles licences utilisées
    - combien d'activations sur cette machine
    - première / dernière activation
    """
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
