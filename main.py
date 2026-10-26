 OSINT SHERLOK — единый main.py (Python 3.11+)
# requirements.txt:
# aiogram>=3.13,<4.0
# phonenumbers>=8.13,<10.0
# aiohttp>=3.9,<4.0
# Pillow>=10.0,<13.0
# maigret>=0.5,<1.0
# beautifulsoup4>=4.12,<5.0
#
# Render: Build: pip install -r requirements.txt | Start: python main.py
# Environment: BOT_TOKEN=<токен от BotFather>
#
# Реально реализовано: телефон (локальные справочные данные), формат email,
# поиск публичных профилей через Maigret, веб-поиск, IP/DNS, EXIF и ссылки Telegram.
# Maigret устанавливается из requirements.txt; поиск зависит от доступности сайтов.
# PhoneInfoga, Holehe, SpiderFoot не подключены автоматически: им нужны отдельные
# установки/настройки. Бот не выдумывает результаты и не ищет закрытые данные.

import asyncio
import html
import ipaddress
import logging
import os
import re
import shutil
import socket
import time
from bs4 import BeautifulSoup
from urllib.parse import quote, urlparse

import phonenumbers
from phonenumbers import carrier, geocoder
from PIL import Image, ExifTags
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "75"))
ENABLE_MAIGRET = os.getenv("ENABLE_MAIGRET", "true").lower() == "true"
ENABLE_SHERLOCK = os.getenv("ENABLE_SHERLOCK", "false").lower() == "true"
MAIGRET_COMMAND = os.getenv("MAIGRET_COMMAND", "maigret")
SHERLOCK_COMMAND = os.getenv("SHERLOCK_COMMAND", "sherlock")

logging.basicConfig(level=logging.INFO)
router = Router()
semaphore = asyncio.Semaphore(2)


def esc(s):
    return html.escape(str(s), quote=False)


def main_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📞 Телефон", callback_data="phone"),
         InlineKeyboardButton(text="✉️ Email", callback_data="email")],
        [InlineKeyboardButton(text="👤 Никнейм: сайты", callback_data="username"),
         InlineKeyboardButton(text="📢 Telegram-группы/каналы", callback_data="tgsearch")],
        [InlineKeyboardButton(text="🌐 IP / домен", callback_data="domain"),
         InlineKeyboardButton(text="🖼 EXIF фото", callback_data="exif")],
        [InlineKeyboardButton(text="🔎 Поиск по открытому интернету", callback_data="websearch")],
        [InlineKeyboardButton(text="🔍 Комплексная проверка", callback_data="full")],
        [InlineKeyboardButton(text="ℹ️ Помощь", callback_data="help")],
    ])


def nav():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="home")],
    ])


def tg_links(query):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="🔎 Искать публичные Telegram-ссылки",
            url="https://www.google.com/search?q=" + quote("site:t.me " + query))],
        [InlineKeyboardButton(
            text="🌐 Искать в интернете",
            url="https://www.google.com/search?q=" + quote(query))],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="home")],
    ])


class Flow(StatesGroup):
    websearch = State()
    phone = State()
    email = State()
    username = State()
    tgsearch = State()
    domain = State()
    exif = State()
    full = State()


WELCOME = (
    "🕵️‍♂️ <b>OSINT SHERLOK</b>\n"
    "<i>Инструменты по открытым источникам</i>\n\n"
    "Выбери проверку в меню.\n\n"
    "⚠️ Результаты могут быть неполными. Бот не получает доступ к закрытым данным."
)

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def phone_check(value):
    try:
        n = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        return "❌ Не распознал номер. Пример: <code>+998901234567</code>."
    if not phonenumbers.is_possible_number(n):
        return "❌ Неподходящая длина или формат номера."
    valid = phonenumbers.is_valid_number(n)
    region = geocoder.description_for_number(n, "ru") or "не определён"
    operator = carrier.name_for_number(n, "ru") or "не определён"
    formatted = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    return (
        f"Номер: <code>{esc(formatted)}</code>\n"
        f"Формат по плану нумерации: {'похож на действительный' if valid else 'не подтверждён'}\n"
        f"Страна/регион: {esc(region)}\nОператор: {esc(operator)}\n\n"
        "Владелец номера и активность SIM-карты не определяются."
    )


def email_check(value):
    if not EMAIL_RE.fullmatch(value):
        return "❌ Формат email выглядит некорректно."
    return (
        "✅ Формат email выглядит корректным.\n\n"
        "Регистрация на сторонних сайтах не проверялась; адрес не отправлялся во внешние сервисы."
    )


async def domain_check(value):
    value = value.strip()
    if not value or len(value) > 253:
        return "❌ Введи IP-адрес или домен."
    try:
        ip = ipaddress.ip_address(value)
        return (
            f"🌐 IP: <code>{esc(ip)}</code>\n"
            f"Тип: {'IPv4' if ip.version == 4 else 'IPv6'}\n"
            f"Глобально маршрутизируемый: {'да' if ip.is_global else 'нет'}\n"
            "Геолокация и сканирование портов не выполнялись."
        )
    except ValueError:
        pass
    host = value.lower().rstrip(".")
    if host.startswith(("http://", "https://")):
        host = urlparse(host).hostname or ""
    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host
    ):
        return "❌ Не распознан IP-адрес или домен."
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=8,
        )
        addresses = sorted({x[4][0] for x in infos})
        addr_text = "\n".join("• <code>" + esc(a) + "</code>" for a in addresses[:10]) or "Адреса не найдены."
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        addr_text = "DNS-адреса не удалось получить (ошибка или тайм-аут)."
    return (
        f"🌐 Домен: <code>{esc(host)}</code>\nDNS-адреса:\n{addr_text}\n\n"
        "WHOIS, сканирование портов и проверка уязвимостей не выполнялись."
    )


async def username_check(username):
    tools = []
    if ENABLE_MAIGRET:
        tools.append(("Maigret", MAIGRET_COMMAND, [username, "--no-progressbar", "--timeout", "10", "-n", "25"]))
    if ENABLE_SHERLOCK:
        tools.append(("Sherlock", SHERLOCK_COMMAND, [username, "--print-found"]))
    if not tools:
        return (
            f"Никнейм: <code>{esc(username)}</code>\n\n"
            "Инструмент поиска профилей не найден на сервере. Проверь Build Logs на Render: "
            "пакет Maigret должен установиться из requirements.txt. Можно также включить "
            "Sherlock отдельной настройкой.\nСовпадение никнейма не подтверждает личность."
        )
    reports = []
    for name, command, args in tools:
        executable = shutil.which(command)
        if not executable:
            reports.append(f"<b>{name}:</b> команда не найдена на сервере.")
            continue
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                executable, *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=REQUEST_TIMEOUT)
            text = output.decode("utf-8", errors="replace")[-2200:]
            reports.append(f"<b>{name} (код {proc.returncode}):</b>\n<pre>{esc(text or 'Нет вывода')}</pre>")
        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            reports.append(f"<b>{name}:</b> тайм-аут.")
        except Exception as exc:
            reports.append(f"<b>{name}:</b> ошибка: {esc(str(exc)[:200])}")
    return (
        f"👤 Никнейм: <code>{esc(username)}</code>\n\n" + "\n\n".join(reports)
        + "\n\n⚠️ Совпадения никнейма не доказывают, что аккаунты принадлежат одному человеку."
    )


# Поиск только по общедоступным веб-страницам. Поисковый запрос передаётся DuckDuckGo.
SENSITIVE_SEARCH_TERMS = (
    "паспорт", "паспортные данные", "домашний адрес", "адрес проживания",
    "прописка", "владелец номера", "на кого зарегистрирован номер",
    "слив базы", "база утечек", "утечка данных", "личные данные паспорта",
)


def web_search_links(query):
    q = quote(query)
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Google", url=f"https://www.google.com/search?q={q}"),
         InlineKeyboardButton(text="Bing", url=f"https://www.bing.com/search?q={q}")],
        [InlineKeyboardButton(text="DuckDuckGo", url=f"https://duckduckgo.com/?q={q}")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="home")],
    ])


async def public_web_search(query):
    query = " ".join(query.split()).strip()
    if not query or len(query) > 180:
        return "❌ Запрос должен быть от 1 до 180 символов.", web_search_links("OSINT")
    lowered = query.casefold()
    if any(term in lowered for term in SENSITIVE_SEARCH_TERMS):
        return (
            "⛔ Не выполняю запросы на поиск паспортных данных, скрытого владельца номера, "
            "домашнего адреса или данных из утечек. Могу искать публичные страницы, "
            "публикации, организации и другие несекретные сведения.",
            web_search_links(""),
        )
    url = "https://html.duckduckgo.com/html/?q=" + quote(query)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-SHERLOK/1.0; +https://duckduckgo.com/)"}
    try:
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url, allow_redirects=True) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}")
                body = await response.text(errors="replace")
        soup = BeautifulSoup(body, "html.parser")
        results = []
        for node in soup.select(".result"):
            title_node = node.select_one(".result__title a")
            snippet_node = node.select_one(".result__snippet")
            if not title_node:
                continue
            title = title_node.get_text(" ", strip=True)
            href = title_node.get("href", "")
            snippet = snippet_node.get_text(" ", strip=True) if snippet_node else ""
            if href.startswith("//"):
                href = "https:" + href
            if not href.startswith("http"):
                continue
            results.append((title[:180], href, snippet[:300]))
            if len(results) >= 6:
                break
        if not results:
            text = (
                f"🔎 <b>Открытый веб-поиск</b>\nЗапрос: <code>{esc(query)}</code>\n\n"
                "Поисковая выдача не вернула читаемые результаты (сайт может ограничивать запросы). "
                "Открой поиск в браузере кнопками ниже."
            )
        else:
            lines = [f"🔎 <b>Открытый веб-поиск</b>\nЗапрос: <code>{esc(query)}</code>\n"]
            for i, (title, href, snippet) in enumerate(results, 1):
                lines.append(f"{i}. <a href=\"{html.escape(href, quote=True)}\">{esc(title)}</a>\n{esc(snippet) if snippet else 'Описание недоступно.'}")
            lines.append("\n⚠️ Это результаты поисковой системы, не подтверждение достоверности. Проверь источник и дату публикации.")
            text = "\n\n".join(lines)
        return text, web_search_links(query)
    except Exception:
        text = (
            f"🔎 <b>Открытый веб-поиск</b>\nЗапрос: <code>{esc(query)}</code>\n\n"
            "Не удалось получить выдачу автоматически: поисковик мог ограничить запрос или соединение истекло. "
            "Попробуй открыть результаты через кнопки ниже."
        )
        return text, web_search_links(query)


async def exif_check(message):
    file_id = None
    filename = "photo"
    if message.photo:
        file_id = message.photo[-1].file_id
    elif message.document:
        if not (message.document.mime_type or "").startswith("image/"):
            return "❌ Пришли файл изображения (например JPG или PNG)."
        file_id = message.document.file_id
        filename = message.document.file_name or "image"
    if not file_id:
        return "❌ Не вижу изображения."
    try:
        from io import BytesIO
        info = await message.bot.get_file(file_id)
        stream = await message.bot.download_file(info.file_path)
        raw = stream.read()
        if len(raw) > 12 * 1024 * 1024:
            return "❌ Файл больше 12 МБ."
        image = Image.open(BytesIO(raw))
        exif = image.getexif()
        lines = []
        tag_names = {v: k for k, v in ExifTags.TAGS.items()}
        for key, val in exif.items():
            name = tag_names.get(key, str(key))
            if name in {"GPSInfo", "MakerNote"}:
                lines.append(f"{name}: метаданные присутствуют (значения не раскрыты)")
            elif isinstance(val, bytes):
                continue
            else:
                lines.append(f"{name}: {str(val)[:180]}")
        if not lines:
            details = "EXIF-метаданные не найдены."
        else:
            details = "<pre>" + esc("\n".join(lines[:30])[:3000]) + "</pre>"
        return (
            f"🖼 Файл: {esc(filename)}\nФормат: {esc(image.format or 'не определён')}\n"
            f"Размер: {image.width} × {image.height}\n\n{details}\n\n"
            "Метаданные могут отсутствовать или быть изменены."
        )
    except Exception as exc:
        return f"❌ Не удалось прочитать изображение: {esc(str(exc)[:200])}"


@router.message(CommandStart())
async def start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(WELCOME, reply_markup=main_menu())


@router.message(Command("help"))
async def help_cmd(message: Message):
    await message.answer(
        "Телефон — справочная проверка; email — формат; никнейм — поиск Maigret/Sherlock; "
        "открытый веб-поиск — поиск публичных страниц; Telegram — ссылки на публичный веб-поиск; "
        "IP/домен — DNS; EXIF — метаданные фото.\n"
        "Закрытые данные, пароли и личные сообщения не извлекаются.",
        reply_markup=main_menu(),
    )


@router.callback_query(F.data == "help")
async def help_button(call: CallbackQuery):
    await call.answer()
    await call.message.edit_text(
        "ℹ️ <b>Возможности</b>\n\nТелефон, формат email, публичный поиск никнейма "
        "(если инструменты установлены), DNS домена, EXIF фото и ссылки на поиск "
        "публичных Telegram-страниц.\n\nЗакрытые данные и личные сообщения недоступны.",
        reply_markup=main_menu(),
    )


@router.callback_query(F.data == "home")
async def home(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await call.answer()
    await call.message.edit_text(WELCOME, reply_markup=main_menu())


@router.callback_query(F.data == "cancel")
async def cancel(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await call.answer("Отменено")
    await call.message.edit_text("Действие отменено.", reply_markup=main_menu())


PROMPTS = {
    "websearch": ("🔎 Отправь поисковый запрос для поиска в открытом интернете. Не вводи пароли, паспортные данные или чужие закрытые сведения.", Flow.websearch),
    "phone": ("📞 Отправь номер в международном формате, например +998901234567.", Flow.phone),
    "email": ("✉️ Отправь email для проверки формата.", Flow.email),
    "username": ("👤 Отправь никнейм без пробелов.", Flow.username),
    "tgsearch": ("📢 Отправь ключевое слово или публичный username для поиска Telegram-страниц.", Flow.tgsearch),
    "domain": ("🌐 Отправь IP-адрес или домен.", Flow.domain),
    "exif": ("🖼 Отправь фото или файл изображения.", Flow.exif),
    "full": ("🔍 Отправь номер, email или никнейм.", Flow.full),
}


@router.callback_query(F.data.in_(list(PROMPTS.keys())))
async def choose(call: CallbackQuery, state: FSMContext):
    prompt, new_state = PROMPTS[call.data]
    await state.set_state(new_state)
    await call.answer()
    await call.message.edit_text(prompt, reply_markup=nav())


@router.message(Flow.websearch)
async def websearch_input(message: Message, state: FSMContext):
    query = (message.text or "").strip()
    status = await message.answer("⏳ Ищу открытые веб-страницы…")
    result, keyboard = await public_web_search(query)
    # Telegram message text limit is 4096 characters; keep room for markup.
    await status.edit_text(result[:3900], reply_markup=keyboard, disable_web_page_preview=True)
    await state.clear()


@router.message(Flow.phone)
async def phone_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if len(value) > 40:
        await message.answer("Слишком длинный номер.", reply_markup=nav())
        return
    await message.answer("📞 <b>Проверка номера</b>\n\n" + phone_check(value), reply_markup=nav())
    await state.clear()


@router.message(Flow.email)
async def email_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if len(value) > 254:
        await message.answer("Слишком длинный email.", reply_markup=nav())
        return
    await message.answer("✉️ <b>Проверка email</b>\n\n" + email_check(value), reply_markup=nav())
    await state.clear()


@router.message(Flow.username)
async def username_input(message: Message, state: FSMContext):
    value = (message.text or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        await message.answer("Никнейм: латинские буквы, цифры, точка, дефис или подчёркивание.", reply_markup=nav())
        return
    status = await message.answer("⏳ Проверяю настроенные инструменты…")
    start_time = time.monotonic()
    async with semaphore:
        result = await username_check(value)
    await status.edit_text(
        "🕵️ <b>OSINT SHERLOK</b>\n\n" + result
        + f"\n\nВремя: {time.monotonic() - start_time:.1f} сек.",
        reply_markup=nav(),
    )
    await state.clear()


@router.message(Flow.tgsearch)
async def tgsearch_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if not value or len(value) > 100:
        await message.answer("Запрос должен быть до 100 символов.", reply_markup=nav())
        return
    await message.answer(
        "📢 <b>Поиск публичных Telegram-страниц</b>\n\n"
        f"Запрос: <code>{esc(value)}</code>\n\n"
        "У Telegram нет универсального API для поиска всех групп и каналов. "
        "Кнопки откроют веб-поиск публичных ссылок; результаты могут быть неполными.",
        reply_markup=tg_links(value),
    )
    await state.clear()


@router.message(Flow.domain)
async def domain_input(message: Message, state: FSMContext):
    await message.answer(await domain_check((message.text or "").strip()), reply_markup=nav())
    await state.clear()


@router.message(Flow.exif, F.photo | F.document)
async def exif_input(message: Message, state: FSMContext):
    await message.answer(await exif_check(message), reply_markup=nav())
    await state.clear()


@router.message(Flow.exif)
async def exif_wrong(message: Message):
    await message.answer("Отправь изображение или нажми «Отмена».", reply_markup=nav())


@router.message(Flow.full)
async def full_input(message: Message, state: FSMContext):
    value = (message.text or "").strip()
    if len(value) > 254:
        await message.answer("Слишком длинный ввод.", reply_markup=nav())
        return
    if EMAIL_RE.fullmatch(value):
        kind, result = "email", email_check(value)
    elif re.fullmatch(r"\+?[0-9()\- .]{7,30}", value):
        kind, result = "телефон", phone_check(value)
    elif re.fullmatch(r"@?[A-Za-z0-9_.-]{1,64}", value):
        kind, result = "никнейм", await username_check(value.lstrip("@"))
    else:
        await message.answer("Не удалось определить тип. Отправь номер, email или никнейм.", reply_markup=nav())
        return
    await message.answer(
        f"🔍 <b>Комплексная проверка: {kind}</b>\n\n{result}\n\n"
        "Выполнены только проверки, доступные в текущей конфигурации.",
        reply_markup=nav(),
    )
    await state.clear()


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("Не задан BOT_TOKEN в Environment на Render.")
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(router)
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
