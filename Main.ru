import asyncio
import ipaddress
import logging
import os
import re
import sys
import time
import aiohttp
from datetime import datetime

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from sqlalchemy import BigInteger, Boolean, DateTime, String
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ==================== КОНФИГУРАЦИЯ ====================
# Можешь вставить токен прямо сюда или передавать через переменные окружения
BOT_TOKEN = os.getenv("BOT_TOKEN", "ТВОЙ_ТОКЕН_ОТ_BOTFATHER")
DATABASE_URL = "sqlite+aiosqlite:///osint_sherlok.db"

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("OSINT-Sherlok")

# ==================== БАЗА ДАННЫХ ====================
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    history_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

class SearchHistory(Base):
    __tablename__ = "search_history"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    query_type: Mapped[str] = mapped_column(String(50))
    query_safe: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50))
    results_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def add_user(user_id: int, username: str | None):
    async with async_session() as session:
        user = await session.get(User, user_id)
        if not user:
            session.add(User(id=user_id, username=username))
            await session.commit()

# ==================== БЕЗОПАСНОСТЬ И ВАЛИДАЦИЯ ====================
def validate_username(username: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_]{3,32}$", username))

def validate_url(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        return True
    except Exception:
        return False

# Rate Limiting
_last_requests: dict[int, float] = {}
async def check_rate_limit(message: Message) -> bool:
    user_id = message.from_user.id
    now = time.time()
    if now - _last_requests.get(user_id, 0) < 1.0:
        return False
    _last_requests[user_id] = now
    return True

# ==================== СЕРВИСЫ ПОИСКА ====================
async def search_by_username(username: str) -> dict:
    if not validate_username(username):
        return {"status": "error", "message": "Неверный формат никнейма (от 3 до 32 символов).", "results": []}
    
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Telegram": f"https://t.me/{username}",
    }
    found = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
        for name, url in platforms.items():
            try:
                async with session.get(url, allow_redirects=True, headers={"User-Agent": "OSINT-Sherlok/1.0"}) as resp:
                    if resp.status == 200:
                        found.append({"source": name, "url": url, "description": f"Профиль найден ({name})", "confidence": "Вероятное"})
            except Exception:
                continue
    return {"status": "найдено" if found else "
