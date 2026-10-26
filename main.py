# OSINT SHERLOK — единый файл main.py
# Python 3.11+
# Установка зависимостей: aiogram>=3.13,<4.0 и phonenumbers>=8.13,<10.0
# На Render задайте переменную окружения BOT_TOKEN.
#
# Важно: эта версия проверяет формат номера/email и локально проверяет IP/домен.
# Поиск по сайтам через Maigret/Sherlock, PhoneInfoga, Holehe, SpiderFoot
# и анализ EXIF здесь НЕ подключены. Бот честно сообщает об этом, а не выдумывает результаты.

import asyncio
import ipaddress
import logging
import os
import re
import time
from urllib.parse import urlparse

import phonenumbers
from phonenumbers import carrier, geocoder
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "25"))

logging.basicConfig(level=logging.INFO)
router = Router()
semaphore = asyncio.Semaphore(2)


# ---------- КЛАВИАТУРЫ ----------

def main_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📞 Поиск по номеру", callback_data="search_phone"),
            InlineKeyboardButton(text="✉️ Проверка email", callback_data="search_email"),
        ],
        [
            InlineKeyboardButton(text="👤 Поиск по никнейму", callback_data="search_username"),
            InlineKeyboardButton(text="🎯 Расширенные инструменты", callback_data="search_advanced"),
        ],
        [
            InlineKeyboardButton(text="🔍 Комплексная проверка", callback_data="search_full"),
        ],
    ])


def navigation():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="home")],
    ])


def advanced_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🌐 IP / домен", callback_data="advanced_domain")],
        [InlineKeyboardButton(text="🖼 Анализ EXIF-фото", callback_data="advanced_exif")],
        [InlineKeyboardButton(text="ℹ️ Telegram-профиль", callback_data="advanced_telegram")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="home")],
    ])


# ---------- СОСТОЯНИЯ ----------

class SearchFlow(StatesGroup):
    phone = State()
    email = State()
    username = State()
    full = State()
    domain = State()
    exif = State()
    telegram = State()


WELCOME = (
    "🕵️‍♂️ <b>OSINT SHERLOK</b>\n"
    "<i>Инструменты поиска по открытым источникам</i>\n\n"
    "Добро пожаловать! Выберите тип проверки.\n\n"
    "⚠️ Используйте только данные, которые вправе проверять. "
    "Бот не получает доступ к закрытым данным."
)

PROMPTS = {
    "search_phone": (
        "📞 Отправьте номер в международном формате, например +998901234567.",
        SearchFlow.phone,
    ),
    "search_email": (
        "✉️ Отправьте email для проверки формата.",
        SearchFlow.email,
    ),
    "search_username": (
        "👤 Отправьте никнейм без пробелов.",
        SearchFlow.username,
    ),
    "search_full": (
        "🔍 Отправьте номер, email или никнейм.",
        SearchFlow.full,
    ),
}


# ---------- ПРОВЕРКИ ----------

def inspect_phone(value: str) -> str:
    try:
        number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        return (
            "❌ Не удалось распознать номер. Используйте международный формат, "
            "например +998901234567."
        )

    if not phonenumbers.is_possible_number(number):
        return "❌ Неподходящая длина или формат номера."

    valid = phonenumbers.is_valid_number(number)
    region = geocoder.description_for_number(number, "ru")
    operator = carrier.name_for_number(number, "ru")

    return (
        f"Формат: {'валидный по нумерационным правилам' if valid else 'возможный, но не подтверждён'}\n"
        f"Страна/регион: {region or 'не определён'}\n"
        f"Оператор: {operator or 'не определён'}\n\n"
        "Это не устанавливает владельца номера и не подтверждает, "
        "что номер сейчас активен."
    )


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def validate_email(value: str) -> str:
    if not EMAIL_RE.fullmatch(value):
        return "❌ Email выглядит некорректно. Проверьте адрес."

    return (
        "✅ Формат email выглядит корректным.\n\n"
        "Проверка регистрации на сторонних сервисах не подключена. "
        "Адрес не отправлялся во внешние сервисы."
    )


def inspect_domain(value: str) -> str:
    value = value.strip()

    try:
        ip = ipaddress.ip_address(value)
        ip_type = "IPv4" if ip.version == 4 else "IPv6"
        return (
            f"🌐 IP-адрес: <code>{ip}</code>\n"
            f"Тип: {ip_type}\n"
            f"Глобально маршрутизируемый: {'да' if ip.is_global else 'нет'}\n\n"
            "Выполнена локальная проверка IP. Сканирование сети не выполнялось."
        )
    except ValueError:
        pass

    candidate = value.lower().rstrip(".")
    if candidate.startswith(("http://", "https://")):
        candidate = urlparse(candidate).hostname or ""

    pattern = (
        r"(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
    )

    if not re.fullmatch(pattern, candidate):
        return "❌ Не распознан IP-адрес или домен."

    return (
        f"🌐 Домен: <code>{candidate}</code>\n"
        "Формат выглядит корректным. Внешние DNS- и WHOIS-запросы "
        "в этой версии не выполняются."
    )


def escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def search_username(username: str) -> str:
    # Интеграция с Maigret/Sherlock намеренно не включена в этот единый файл.
    # Не показываем выдуманные найденные профили.
    await asyncio.sleep(0)
    return (
        f"Никнейм: <code>{escape_html(username)}</code>\n\n"
        "Поиск по внешним сайтам пока не подключён. "
        "Профили не проверялись; результаты не выдумывались."
    )


# ---------- ОБРАБОТЧИКИ ----------

@router.message(CommandStart())
async def start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(WELCOME, reply_markup=main_menu())


@router.message(Command("help"))
async def help_command(message: Message):
    await message.answer(
        "Выберите направление в меню. Проверяются только открытые данные "
        "и корректность введённых значений.",
        reply_markup=main_menu(),
    )


@router.callback_query(F.data == "home")
async def home(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.answer()
    await callback.message.edit_text(WELCOME, reply_markup=main_menu())


@router.callback_query(F.data == "search_advanced")
async def advanced(callback: CallbackQuery):
    await callback.answer()
    await callback.message.edit_text(
        "🎯 <b>Расширенные инструменты</b>\n\nВыберите действие:",
        reply_markup=advanced_menu(),
    )


@router.callback_query(F.data.in_(list(PROMPTS.keys())))
async def choose_search(callback: CallbackQuery, state: FSMContext):
    prompt, new_state = PROMPTS[callback.data]
    await state.set_state(new_state)
    await callback.answer()
    await callback.message.edit_text(prompt, reply_markup=navigation())


@router.callback_query(F.data == "cancel")
async def cancel(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.answer("Отменено")
    await callback.message.edit_text(
        "Действие отменено. Выберите следующий пункт:",
        reply_markup=main_menu(),
    )


@router.callback_query(F.data == "advanced_domain")
async def ask_domain(callback: CallbackQuery, state: FSMContext):
    await state.set_state(SearchFlow.domain)
    await callback.answer()
    await callback.message.edit_text(
        "🌐 Отправьте IP-адрес или домен.",
        reply_markup=navigation(),
    )


@router.callback_query(F.data == "advanced_exif")
async def ask_exif(callback: CallbackQuery, state: FSMContext):
    await state.set_state(SearchFlow.exif)
    await callback.answer()
    await callback.message.edit_text(
        "🖼 Анализ EXIF пока не подключён. Отправьте фото, чтобы получить сообщение о статусе.",
        reply_markup=navigation(),
    )


@router.callback_query(F.data == "advanced_telegram")
async def ask_telegram(callback: CallbackQuery, state: FSMContext):
    await state.set_state(SearchFlow.telegram)
    await callback.answer()
    await callback.message.edit_text(
        "ℹ️ Отправьте публичный Telegram username, например @username. "
        "Скрытые данные недоступны.",
        reply_markup=navigation(),
    )


@router.message(SearchFlow.phone)
async def phone_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if len(value) > 40:
        await message.answer("Слишком длинный номер.", reply_markup=navigation())
        return
    await message.answer(
        "📞 <b>Проверка номера</b>\n\n" + inspect_phone(value),
        reply_markup=navigation(),
    )
    await state.clear()


@router.message(SearchFlow.email)
async def email_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if len(value) > 254:
        await message.answer("Email слишком длинный.", reply_markup=navigation())
        return
    await message.answer(
        "✉️ <b>Проверка email</b>\n\n" + validate_email(value),
        reply_markup=navigation(),
    )
    await state.clear()


@router.message(SearchFlow.username)
async def username_input(message: Message, state: FSMContext):
    value = (message.text or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        await message.answer(
            "Никнейм должен содержать латинские буквы, цифры, точку, "
            "дефис или подчёркивание.",
            reply_markup=navigation(),
        )
        return

    async with semaphore:
        await message.bot.send_chat_action(message.chat.id, "typing")
        status = await message.answer("⏳ Проверка…")
        started = time.monotonic()
        result = await search_username(value)
        await status.edit_text(
            "🕵️ <b>OSINT SHERLOK</b>\n\n"
            f"{result}\n\n"
            f"Время выполнения: {time.monotonic() - started:.1f} сек.",
            reply_markup=navigation(),
        )
    await state.clear()


@router.message(SearchFlow.full)
async def full_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if len(value) > 254:
        await message.answer("Слишком длинный ввод.", reply_markup=navigation())
        return

    if "@" in value and "." in value and not value.startswith("@"):
        kind = "email"
        result = validate_email(value)
    elif re.fullmatch(r"\+?[0-9()\- .]{7,30}", value):
        kind = "номер телефона"
        result = inspect_phone(value)
    elif re.fullmatch(r"@?[A-Za-z0-9_.-]{1,64}", value):
        kind = "никнейм"
        result = await search_username(value.lstrip("@"))
    else:
        await message.answer(
            "Не удалось определить тип. Отправьте номер, email или никнейм.",
            reply_markup=navigation(),
        )
        return

    await message.answer(
        "🔍 <b>Комплексная проверка</b>\n\n"
        f"Тип данных: {kind}\n\n{result}\n\n"
        "В этой версии выполнена только доступная локальная проверка.",
        reply_markup=navigation(),
    )
    await state.clear()


@router.message(SearchFlow.domain)
async def domain_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    await message.answer(inspect_domain(value), reply_markup=navigation())
    await state.clear()


@router.message(SearchFlow.telegram)
async def telegram_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if not re.fullmatch(r"@?[A-Za-z0-9_]{5,32}", value):
        await message.answer(
            "Введите корректный публичный username Telegram.",
            reply_markup=navigation(),
        )
        return

    username = value.lstrip("@")
    await message.answer(
        f"ℹ️ Публичный username: <code>{escape_html(username)}</code>\n\n"
        "Проверка скрытых данных не выполняется. "
        "Эта версия только проверила формат username.",
        reply_markup=navigation(),
    )
    await state.clear()


@router.message(SearchFlow.exif, F.photo | F.document)
async def exif_file(message: Message, state: FSMContext):
    await message.answer(
        "Анализ EXIF пока не подключён. Файл не скачивался и не анализировался.",
        reply_markup=navigation(),
    )
    await state.clear()


@router.message(SearchFlow.exif)
async def exif_wrong_input(message: Message):
    await message.answer(
        "Отправьте изображение или нажмите «Отмена».",
        reply_markup=navigation(),
    )


async def main():
    if not BOT_TOKEN:
        raise RuntimeError(
            "Не задан BOT_TOKEN. Добавьте его в Environment на Render."
        )

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher()
    dp.include_router(router)

    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
