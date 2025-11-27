import os
from datetime import datetime
from typing import Optional
from collections import defaultdict
from urllib.parse import quote
import json   
import requests
from fastapi import FastAPI, Depends, Request, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles  # <-- pour servir /static/logo.png
from pydantic import BaseModel, EmailStr

from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# =========================
#   CONFIG
# =========================

# 1) On Render: DATABASE_URL est automatiquement fournie (postgresql://...)
# 2) En local: si non définie, fallback SQLite
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./activations.db"

# Only add connect_args for SQLite
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

APP_TITLE = "Phoenix License Tracker"
APP_VERSION = "1.0.0"

# Secret pour la commande de reset DB (compat /admin/reset-db)
ADMIN_DELETE_SECRET = os.getenv("ADMIN_DELETE_SECRET", "phoenix_super_reset_2024")

# Mot de passe Admin pour confirmer un effacement via le Dashboard
ADMIN_DASHBOARD_PASSWORD = os.getenv("ADMIN_DASHBOARD_PASSWORD", "admin123")


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
    - LICENSE_EXPIRED_LOCAL
    - LICENSE_DELETED_LOCAL
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

# === STATIC FILES pour le logo du dashboard ===
# Dossier attendu :
#   main.py
#   static/
#       logo.png
app.mount("/static", StaticFiles(directory="static"), name="static")


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


class LicenseLifecycleEventIn(BaseModel):
    """
    Événement de cycle de vie de la licence (coté client Phoenix) :
    - LICENSE_EXPIRED_LOCAL : la licence est arrivée à expiration sur la machine,
      le client a supprimé le license.json
    - LICENSE_DELETED_LOCAL : l'utilisateur / admin a supprimé le fichier local
    - LICENSE_RESET_LOCAL   : autre reset local explicite
    - LICENSE_REVOKED_REMOTE: nettoyage local après révocation distante
    etc.

    Ces événements sont aussi stockés dans UsageEvent.
    """
    app_id: str
    app_version: str
    license_key: str
    fingerprint: str
    event_type: str          # ex: LICENSE_EXPIRED_LOCAL, LICENSE_DELETED_LOCAL, ...
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

    Règles :
    - On autorise la 1ère activation pour une paire (license_key, fingerprint).
    - Si la même clé est réutilisée sur la même machine, on enregistre l'activation
      (pour l'historique) MAIS on marque la paire comme RÉVOQUÉE (one-shot).
    """

    # 1) Combien d'activations existe déjà pour cette paire (license_key + fingerprint) ?
    existing_pair_count = (
        db.query(Activation)
        .filter(
            Activation.license_key == data.license_key,
            Activation.fingerprint == data.fingerprint,
        )
        .count()
    )
    is_first_for_pair = existing_pair_count == 0

    # 2) On enregistre l'activation (comme avant, pour garder l'historique complet)
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

    # 3) Stat globales (inchangées)
    total = db.query(Activation).count()

    machine_count = (
        db.query(Activation)
        .filter(Activation.fingerprint == data.fingerprint)
        .count()
    )
    is_first_for_machine = machine_count == 1

    # 4) Si ce n'est PAS la première fois qu'on voit cette PAIRE (license_key + fingerprint)
    #    => on AUTO-RÉVOQUE cette paire (clé one-shot pour cette machine)
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

    # 5) Message Telegram standard (comme avant) + info si auto-revoked
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
    return {
        "fingerprint": fingerprint,
        "activations": machine_count,
    }


# =========================
#   RÉVOCATION (avec query + compat)
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

    return {
        "status": status,
        "license_key": license_key,
        "fingerprint": fingerprint,
        "via": method,
    }


@app.api_route("/revoke", methods=["GET", "POST"])
def revoke_license_on_machine(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
    request: Request = None,
):
    method = request.method if request else "UNKNOWN"
    return _revoke_pair_core(license_key, fingerprint, db, method)


# compat ancienne URL /revoke/{license_key}/{fingerprint}
# avec license_key qui peut contenir des "/"
@app.api_route("/revoke/{path_data:path}", methods=["GET", "POST"])
def revoke_license_on_machine_compat(
    path_data: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    """
    Compat pour les anciennes URLs du type :
        /revoke/<license_key_avec_des_/...>/<fingerprint>

    On récupère tout après /revoke/ dans path_data,
    puis on coupe sur le DERNIER "/" pour séparer licence et fingerprint.
    """
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

    return {
        "status": status,
        "license_key": license_key,
        "fingerprint": fingerprint,
        "via": method,
    }


@app.api_route("/unrevoke", methods=["GET", "POST"])
def unrevoke_license_on_machine(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
    request: Request = None,
):
    method = request.method if request else "UNKNOWN"
    return _unrevoke_pair_core(license_key, fingerprint, db, method)


# compat ancienne URL /unrevoke/{license_key}/{fingerprint}
# avec license_key qui peut contenir des "/"
@app.api_route("/unrevoke/{path_data:path}", methods=["GET", "POST"])
def unrevoke_license_on_machine_compat(
    path_data: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    """
    Compat pour les anciennes URLs du type :
        /unrevoke/<license_key_avec_des_/...>/<fingerprint>
    """
    if "/" not in path_data:
        raise HTTPException(status_code=400, detail="Invalid unrevoke path")

    license_key, fingerprint = path_data.rsplit("/", 1)

    method = request.method if request else "UNKNOWN"
    return _unrevoke_pair_core(license_key, fingerprint, db, method)


# ========= License status (client Phoenix) =========

# Nouveau endpoint (query params)
@app.get("/license/status")
def license_status_query(
    license_key: str = Query(...),
    fingerprint: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Vérifie si une paire (license_key, fingerprint) est révoquée.
    Utilisé par le client Phoenix :

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


# Ancien endpoint (compat path params)
@app.get("/license/status/{license_key}/{fingerprint}")
def license_status_compat(
    license_key: str,
    fingerprint: str,
    db: Session = Depends(get_db),
):
    return license_status_query(license_key=license_key, fingerprint=fingerprint, db=db)


# ========= License lifecycle events (expiration / suppression locale) =========

@app.post("/license/event")
def license_lifecycle_event(
    event: LicenseLifecycleEventIn,
    db: Session = Depends(get_db),
):
    """
    Endpoint pour que le CLIENT Phoenix notifie le serveur Render
    d'un événement de cycle de vie de licence, par exemple :

    - LICENSE_EXPIRED_LOCAL : licence arrivée à expiration sur la machine
      (le client a supprimé license.json localement)
    - LICENSE_DELETED_LOCAL : suppression manuelle du fichier licence sur cette machine
    - LICENSE_RESET_LOCAL   : reset volontaire côté client
    - LICENSE_REVOKED_REMOTE: nettoyage local après révocation distante

    Effets :
    - Enregistre un UsageEvent supplémentaire (dashboard /admin → Last usage events)
    - Envoie une notification Telegram avec le détail machine / licence / type d'événement
    """

    row = UsageEvent(
        app_id=event.app_id,
        app_version=event.app_version,
        license_key=event.license_key,
        fingerprint=event.fingerprint,
        event_type=event.event_type,
        event_source="PhoenixClient",   # source technique pour ce type d’événement
        details=event.details or "",
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # Notification Telegram dédiée avec message adapté
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
#   ADMIN: DB DELETE COMMAND
# =========================

@app.post("/admin/delete-all")
def admin_delete_all(secret: str = Query(...), db: Session = Depends(get_db)):
    """
    Supprime TOUTES les données (activations, usages, révocations).

    Appel:
        POST /admin/delete-all?secret=VOTRE_SECRET

    Configurez ADMIN_DELETE_SECRET dans les variables d'environnement Render.
    """
    if not ADMIN_DELETE_SECRET:
        raise HTTPException(status_code=500, detail="ADMIN_DELETE_SECRET not configured")

    if secret != ADMIN_DELETE_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    deleted_usage = db.query(UsageEvent).delete()
    deleted_revocations = db.query(RevokedLicenseMachine).delete()
    deleted_activations = db.query(Activation).delete()
    db.commit()

    send_telegram_message(
        f"⚠️ ADMIN DELETE ALL\n\n"
        f"Deleted activations: {deleted_activations}\n"
        f"Deleted usage events: {deleted_usage}\n"
        f"Deleted revocations: {deleted_revocations}"
    )

    return {
        "status": "ok",
        "deleted_activations": deleted_activations,
        "deleted_usage_events": deleted_usage,
        "deleted_revocations": deleted_revocations,
    }


@app.get("/admin/reset-db")
def admin_reset_db(token: str = Query(...), db: Session = Depends(get_db)):
    """
    Alias rétro-compatible :
        GET /admin/reset-db?token=...
    utilise le même secret qu'ADMIN_DELETE_SECRET
    et appelle la même logique que /admin/delete-all.
    """
    if token != ADMIN_DELETE_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    # on réutilise la fonction existante admin_delete_all
    return admin_delete_all(secret=token, db=db)


@app.post("/admin/confirm-delete")
def admin_confirm_delete(
    password: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Confirme l'effacement depuis le dashboard admin via mot de passe.
    - Vérifie ADMIN_DASHBOARD_PASSWORD
    - Puis appelle admin_delete_all avec ADMIN_DELETE_SECRET
    """
    if password != ADMIN_DASHBOARD_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin password")

    # On appelle la suppression globale avec le secret interne
    return admin_delete_all(secret=ADMIN_DELETE_SECRET, db=db)


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

    * {
        box-sizing: border-box;
    }

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

    .topbar-title {
        display: flex;
        align-items: center;
        gap: 10px;
    }

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

    .topbar-text-main {
        font-weight: 600;
        font-size: 16px;
    }

    .topbar-text-sub {
        font-size: 11px;
        color: var(--muted);
    }

    .topbar-pills {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 11px;
    }

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

    .breadcrumbs {
        font-size: 12px;
        margin-bottom: 8px;
        color: var(--muted);
    }

    .breadcrumbs a {
        color: #93c5fd;
        text-decoration: none;
    }
    .breadcrumbs a:hover {
        text-decoration: underline;
    }

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

    .card-muted {
        background: #020617;
    }

    .card-title {
        font-size: 12px;
        color: var(--muted);
    }
    .card-value {
        font-size: 22px;
        font-weight: 600;
        margin-top: 4px;
    }
    .card-extra {
        font-size: 11px;
        color: var(--text-soft);
        margin-top: 2px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 12px;
        border-radius: var(--radius);
        overflow: hidden;
    }

    thead {
        position: sticky;
        top: 52px;
        z-index: 10;
    }

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

    tr.row-warning td {
        background: rgba(250,204,21,0.04);
    }
    tr.row-danger td {
        background: rgba(248,113,113,0.07);
    }

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

    .pill-actions {
        margin-top: 4px;
        font-size: 11px;
    }
    .pill-actions a {
        margin-right: 8px;
    }

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
    .btn-danger:hover {
        background: linear-gradient(to right, #dc2626, #f97373);
    }

    .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 10px;
    }

    .toolbar-right {
        display: flex;
        gap: 8px;
        align-items: center;
    }

    .input-search {
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid var(--border-subtle);
        background: #020617;
        color: var(--text);
        font-size: 12px;
        min-width: 180px;
    }
    .input-search::placeholder {
        color: #6b7280;
    }

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

    .danger-zone-header {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #fecaca;
    }

    /* === Réseau machines / licences === */
    .network-card {
        margin-top: 12px;
    }

    .network-nodes {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 10px;
    }

    .network-node-card {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-decoration: none;
        border-radius: 10px;
        padding: 8px 10px;
        border: 1px solid var(--border-subtle);
        background: #020617;
        min-width: 120px;
        max-width: 160px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.35);
    }

    .network-node-icon {
        font-size: 20px;
        margin-bottom: 2px;
    }

    .network-node-fp {
        font-size: 10px;
        color: var(--muted);
        text-align: center;
        word-break: break-all;
        margin-top: 4px;
    }

    .network-node-ok {
        border-color: #16a34a;
        box-shadow: 0 0 0 1px rgba(34,197,94,0.4);
    }

    .network-node-bad {
        border-color: #b91c1c;
        box-shadow: 0 0 0 1px rgba(248,113,113,0.45);
    }

    .network-node-admin-card {
        border-width: 1.5px;
        border-color: var(--accent);
        box-shadow: 0 0 0 1px rgba(59,130,246,0.6);
    }
"""

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

    # Dernier événement LICENSE_DELETED_LOCAL par license_key pour cette machine
    deleted_rows = (
        db.query(
            UsageEvent.license_key,
            func.max(UsageEvent.created_at),
        )
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

    # Dernière activation (par license) pour cette machine
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
        current_revoked = (
            db.query(RevokedLicenseMachine)
            .filter(
                RevokedLicenseMachine.license_key == current_activation.license_key,
                RevokedLicenseMachine.fingerprint == current_activation.fingerprint,
            )
            .first()
            is not None
        )
        current_expired = bool(current_activation.expires_at and current_activation.expires_at < now)

        deleted_at_current = deleted_by_license.get(current_activation.license_key)
        is_deleted_current = bool(
            deleted_at_current
            and current_activation.activated_at
            and deleted_at_current >= current_activation.activated_at
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
        Fingerprint:
        <span class="badge badge-green">{fingerprint}</span>
        &nbsp; {machine_status_badge}
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
    if licenses:
        current_license_key = current_activation.license_key if current_activation else None
        current_revoked_flag = (
            current_activation
            and current_activation.license_key in revoked_license_keys
        )
        current_expired_flag = bool(current_activation and current_activation.expires_at and current_activation.expires_at < now)

        for lk in licenses:
            safe_lk = quote(lk or "", safe="")
            safe_fp = quote(fingerprint or "", safe="")

            last_act_for_lk = last_activation_for_license.get(lk)
            deleted_at = deleted_by_license.get(lk)
            is_deleted = bool(
                deleted_at
                and last_act_for_lk
                and last_act_for_lk.activated_at
                and deleted_at >= last_act_for_lk.activated_at
            )

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
                <a href="/admin/license/{safe_lk}">{lk}</a>
                &nbsp;{badge}
                <span class="pill-actions">
                    <a href="{revoke_link}">Revoke</a>·
                    <a href="{unrevoke_link}">Unrevoke</a>
                </span>
            </li>
            """
    else:
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
                    <th>Status</th>
                    <th>User</th>
                    <th>Activated at</th>
                    <th>Expires at</th>
                </tr>
            </thead>
            <tbody>
    """
    current_id = current_activation.id if current_activation else None
    for a in activations:
        user_name = ((a.user_first_name or "") + " " + (a.user_last_name or "")).strip() or "—"
        act = a.activated_at.isoformat() if a.activated_at else ""
        exp = a.expires_at.isoformat() if a.expires_at else ""

        pair_revoked = (
            db.query(RevokedLicenseMachine)
            .filter(
                RevokedLicenseMachine.license_key == a.license_key,
                RevokedLicenseMachine.fingerprint == a.fingerprint,
            )
            .first()
            is not None
        )
        is_expired = bool(a.expires_at and a.expires_at < now)
        is_latest = (a.id == current_id)

        deleted_at = deleted_by_license.get(a.license_key)
        is_deleted = bool(
            deleted_at
            and a.activated_at
            and deleted_at >= a.activated_at
        )

        if pair_revoked:
            status_badge = '<span class="badge badge-red">Revoked</span>'
        elif is_deleted and is_latest:
            status_badge = '<span class="badge badge-red">Deleted locally</span>'
        elif is_expired:
            status_badge = '<span class="badge badge-red">Expired</span>'
        elif is_latest:
            status_badge = '<span class="badge badge-green">Active</span>'
        else:
            status_badge = '<span class="badge badge-red">Inactive</span>'

        safe_lk = quote(a.license_key or "", safe="")
        safe_fp = quote(a.fingerprint or "", safe="")

        revoke_link = f"/revoke?license_key={safe_lk}&fingerprint={safe_fp}"
        unrevoke_link = f"/unrevoke?license_key={safe_lk}&fingerprint={safe_fp}"

        html += f"""
                <tr>
                    <td>{a.id}</td>
                    <td><a href="/admin/license/{safe_lk}" class="badge badge-blue">{a.license_key}</a></td>
                    <td>
                        {status_badge}
                        <div class="pill-actions">
                            <a href="{revoke_link}">Revoke</a>·
                            <a href="{unrevoke_link}">Unrevoke</a>
                        </div>
                    </td>
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
"""

    if revoked_rows:
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
        for r in revoked_rows:
            rev_at = r.revoked_at.isoformat() if r.revoked_at else ""
            safe_lk = quote(r.license_key or "", safe="")
            html += f"""
                <tr>
                    <td>{r.id}</td>
                    <td><a href="/admin/license/{safe_lk}">{r.license_key}</a></td>
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

# IMPORTANT : {license_key:path} pour autoriser "/" dans la licence
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
        db.query(
            UsageEvent.fingerprint,
            func.max(UsageEvent.created_at),
        )
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
        is_deleted = bool(
            deleted_at
            and latest_for_license
            and latest_for_license.activated_at
            and deleted_at >= latest_for_license.activated_at
        )

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

    active_machines_set = {fp for fp, st in pair_status_by_fp.items() if st == "active"}
    revoked_machine_count = len(revoked_fingerprints)
    deleted_machine_count = len([fp for fp, st in pair_status_by_fp.items() if st == "deleted"])
    active_machine_count = len(active_machines_set)

    if active_machine_count > 0:
        license_status_badge = f'<span class="badge badge-green">Active on {active_machine_count} machine(s)</span>'
    elif deleted_machine_count > 0:
        license_status_badge = f'<span class="badge badge-red">Deleted locally on {deleted_machine_count} machine(s)</span>'
    elif revoked_machine_count > 0:
        license_status_badge = f'<span class="badge badge-red">No active machines ({revoked_machine_count} revoked)</span>'
    else:
        license_status_badge = '<span class="badge badge-red">No active machines</span>'

    safe_lk_global = quote(license_key or "", safe="")

    last_activation_id_for_fp = {}
    for a in activations:
        fp = a.fingerprint
        if fp:
            last_activation_id_for_fp[fp] = a.id

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
        &nbsp; {license_status_badge}
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
            <div class="card-title">Active machines</div>
            <div class="card-value">{active_machine_count}</div>
        </div>
        <div class="card">
            <div class="card-title">Revoked machines</div>
            <div class="card-value">{revoked_machine_count}</div>
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
                <a href="/admin/machine/{safe_fp}">{fp}</a>
                &nbsp;{badge}
                <span class="pill-actions">
                    <a href="{revoke_link}">Revoke</a>·
                    <a href="{unrevoke_link}">Unrevoke</a>
                </span>
            </li>
            """
    else:
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
                    <th>Status</th>
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

        fp = a.fingerprint
        pair_revoked = fp in revoked_fingerprints
        is_expired = bool(a.expires_at and a.expires_at < now)

        latest_global = last_global_for_fp.get(fp)
        is_current_license_on_machine = bool(latest_global and latest_global.license_key == license_key)
        is_last_activation_of_license_for_fp = (last_activation_id_for_fp.get(fp) == a.id)

        deleted_at = deleted_by_fp.get(fp)
        is_deleted_on_last = bool(
            deleted_at
            and is_last_activation_of_license_for_fp
            and a.activated_at
            and deleted_at >= a.activated_at
        )

        if pair_revoked:
            status_badge = '<span class="badge badge-red">Revoked</span>'
        elif is_deleted_on_last:
            status_badge = '<span class="badge badge-red">Deleted locally</span>'
        elif is_expired:
            status_badge = '<span class="badge badge-red">Expired</span>'
        elif is_current_license_on_machine and is_last_activation_of_license_for_fp:
            status_badge = '<span class="badge badge-green">Active</span>'
        else:
            status_badge = '<span class="badge badge-red">Inactive</span>'

        safe_fp = quote(fp or "", safe="")

        revoke_link = f"/revoke?license_key={safe_lk_global}&fingerprint={safe_fp}"
        unrevoke_link = f"/unrevoke?license_key={safe_lk_global}&fingerprint={safe_fp}"

        html += f"""
                <tr>
                    <td>{a.id}</td>
                    <td><a href="/admin/machine/{safe_fp}" class="badge badge-green">{a.fingerprint}</a></td>
                    <td>
                        {status_badge}
                        <div class="pill-actions">
                            <a href="{revoke_link}">Revoke</a>·
                            <a href="{unrevoke_link}">Unrevoke</a>
                        </div>
                    </td>
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
        raw_details = u.details or ""
        display_details = raw_details

        # --- Formatage propre du JSON (chatbot, app_open, module...) ---
        try:
            s = raw_details.strip()
            if s.startswith("{") and s.endswith("}"):
                obj = json.loads(s)

                # Chatbot messages
                if "role" in obj and "message" in obj:
                    display_details = f"{obj['role']}: {obj['message']}"
                # Module open
                elif "module" in obj:
                    display_details = f"Module: {obj['module']}"
                # App open / platform info
                elif "platform" in obj or "platform_release" in obj:
                    plat = obj.get("platform", "")
                    rel = obj.get("platform_release", "")
                    pyv = obj.get("python_version", "")
                    parts = [p for p in [plat + (" " + rel if rel else ""), f"Python {pyv}" if pyv else ""] if p]
                    display_details = " • ".join(parts) or raw_details
                else:
                    # fallback: k=v, k2=v2...
                    display_details = ", ".join(f"{k}={v}" for k, v in obj.items())
        except Exception:
            display_details = raw_details

        if len(display_details) > 80:
            display_details = display_details[:80] + "..."

        safe_fp = quote(u.fingerprint or "", safe="")
        html += f"""
                <tr>
                    <td>{u.id}</td>
                    <td><span class="badge badge-blue">{u.event_type}</span></td>
                    <td>{u.event_source}</td>
                    <td class="small"><a href="/admin/machine/{safe_fp}">{u.fingerprint}</a></td>
                    <td>{created}</td>
                    <td class="small">{display_details}</td>
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
            safe_fp = quote(r.fingerprint or "", safe="")
            html += f"""
                <tr>
                    <td>{r.id}</td>
                    <td><a href="/admin/machine/{safe_fp}">{r.fingerprint}</a></td>
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
