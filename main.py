import os
from datetime import datetime

from fastapi import FastAPI, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session

import requests

# =========================
#   CONFIG
# =========================

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./activations.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Phoenix License Tracker", version="1.0.0")


# =========================
#   DB MODEL
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


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
#   TELEGRAM
# =========================

def send_telegram_message(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[telegram] not configured, skipping message")
        return

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            print(f"[telegram] send failed: {r.status_code} {r.text}")
        else:
            print("[telegram] message sent")
    except Exception as e:
        print(f"[telegram] error: {e}")


# =========================
#   SCHEMAS
# =========================

class UserInfo(BaseModel):
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
    user: UserInfo


class ActivationOut(BaseModel):
    activation_id: int
    total_activations: int


# =========================
#   ROUTES
# =========================

@app.get("/")
def root():
    return {
        "status": "running",
        "time": int(datetime.utcnow().timestamp())
    }


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    """
    Retourne le nombre TOTAL d'activations enregistrées (toutes machines, toutes licences).
    """
    total = db.query(Activation).count()
    return {"total_activations": total}


@app.post("/activation", response_model=ActivationOut)
def register_activation(data: ActivationIn, db: Session = Depends(get_db)):
    """
    Enregistre une activation dans la base.
    ⚠️ IMPORTANT : on crée une nouvelle entrée à CHAQUE appel,
    on ne fait PAS de 'get or create' ni de déduplication.
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

    # Message Telegram
    msg_lines = [
        "🧾 PHOENIX License Activation",
        f"App: {data.app_id} v{data.app_version} ({data.license_scope})",
        f"Fingerprint: {data.fingerprint}",
        f"License key: {data.license_key}",
        "",
        f"User: {data.user.first_name} {data.user.last_name}",
        f"Email: {data.user.email}",
        f"Phone: {data.user.phone}",
        "",
        f"Activated at: {datetime.utcfromtimestamp(data.activated_at).isoformat()}",
        f"Expires at: {datetime.utcfromtimestamp(data.expires_at).isoformat()}",
        "",
        f"Total activations: {total}",
    ]
    send_telegram_message("\n".join(msg_lines))

    return ActivationOut(
        activation_id=activation.id,
        total_activations=total,
    )
