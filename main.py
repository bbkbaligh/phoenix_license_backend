import os
import time
from datetime import datetime
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, EmailStr

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ===================== CONFIG =====================

# Tu peux laisser les valeurs par défaut (pour dev),
# mais sur Render on les mettra en variables d'environnement.
TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN",
    "7670687318:AAEi2RppVza3KfR6ALAYvPjWvbiat8BI_Is"  # ton token existant
)
TELEGRAM_CHAT_ID = os.getenv(
    "TELEGRAM_CHAT_ID",
    "6508018960"  # ton chat_id admin
)

# Base SQLite locale (Render supporte bien ça pour un petit tracker)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./activations.db")


# ===================== DB SETUP =====================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Activation(Base):
    __tablename__ = "activations"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String, index=True)
    app_version = Column(String)
    license_scope = Column(String)
    license_key = Column(String, index=True)
    fingerprint = Column(String, index=True)
    user_first_name = Column(String)
    user_last_name = Column(String)
    user_email = Column(String, index=True)
    user_phone = Column(String)
    activated_at = Column(DateTime)
    expires_at = Column(DateTime)


Base.metadata.create_all(bind=engine)


# ===================== SCHEMAS Pydantic =====================

class UserInfo(BaseModel):
    first_name: str = Field(..., max_length=100)
    last_name: str = Field(..., max_length=100)
    email: EmailStr
    phone: Optional[str] = ""


class ActivationPayload(BaseModel):
    app_id: str
    app_version: str
    license_scope: str
    license_key: str
    fingerprint: str
    activated_at: int   # timestamp en secondes (int time.time())
    expires_at: int     # timestamp en secondes
    user: UserInfo


class ActivationResponse(BaseModel):
    status: str
    activation_id: int
    total_activations: int


# ===================== APP FastAPI =====================

app = FastAPI(title="PHOENIX License Tracker API")


def send_telegram_message(text: str):
    """
    Envoie un message Telegram au chat admin.
    Si le token ou le chat_id n'est pas configuré, on log juste.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[telegram] not configured, skipping message")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            print(f"[telegram] send failed: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[telegram] error: {e}")


@app.post("/activation", response_model=ActivationResponse)
def register_activation(payload: ActivationPayload):
    """
    Endpoint appelé par l'application PyQt5 à chaque activation de licence.
    - Sauvegarde en DB
    - Envoie une notification Telegram
    - Retourne le nombre total d'activations
    """
    db = SessionLocal()
    try:
        activated_dt = datetime.fromtimestamp(payload.activated_at)
        expires_dt = datetime.fromtimestamp(payload.expires_at)

        activation = Activation(
            app_id=payload.app_id,
            app_version=payload.app_version,
            license_scope=payload.license_scope,
            license_key=payload.license_key,
            fingerprint=payload.fingerprint,
            user_first_name=payload.user.first_name,
            user_last_name=payload.user.last_name,
            user_email=payload.user.email,
            user_phone=payload.user.phone or "",
            activated_at=activated_dt,
            expires_at=expires_dt,
        )

        db.add(activation)
        db.commit()
        db.refresh(activation)

        total = db.query(Activation).count()

        # Message Telegram
        msg = (
            f"<b>PHOENIX License Activation</b>\n"
            f"App: {payload.app_id} v{payload.app_version} ({payload.license_scope})\n\n"
            f"<b>User</b>\n"
            f"  - Name: {payload.user.first_name} {payload.user.last_name}\n"
            f"  - Email: {payload.user.email}\n"
            f"  - Phone: {payload.user.phone or 'N/A'}\n\n"
            f"<b>Machine</b>\n"
            f"  - Fingerprint: <code>{payload.fingerprint}</code>\n\n"
            f"<b>License</b>\n"
            f"  - Key: <code>{payload.license_key}</code>\n"
            f"  - Activated: {activated_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  - Expires: {expires_dt.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"<b>Total activations:</b> {total}"
        )

        send_telegram_message(msg)

        return ActivationResponse(
            status="ok",
            activation_id=activation.id,
            total_activations=total,
        )
    except Exception as e:
        db.rollback()
        print(f"[activation] error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        db.close()


@app.get("/")
def root():
    return {"status": "running", "time": int(time.time())}


@app.get("/stats")
def stats():
    """
    Petit endpoint de stats: nombre total d'activations.
    Tu peux l'ouvrir dans le navigateur.
    """
    db = SessionLocal()
    try:
        total = db.query(Activation).count()
        return {"total_activations": total}
    finally:
        db.close()
