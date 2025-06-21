"""Основной модуль Telegram бота."""

import asyncio
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
import json

from aiogram import Bot, Dispatcher, types
from aiogram.filters.command import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

from src.core.dns_checker import DNSChecker
from src.core.scheduler import DomainCheckScheduler
from src.core.whois_checker import WhoisChecker
from src.db.service import DatabaseService
from src.utils.config import load_config
from src.utils.validators import is_valid_domain

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class DomainForm(StatesGroup):
    """Состояния формы добавления домена."""
    waiting_for_domain = State()
    waiting_for_interval = State()


class WhoisCheckerBot:
    """Основной класс бота."""

    def __init__(self):
        """Инициализация бота."""
        self.config = load_config()
        self.bot = Bot(token=self.config["bot"]["token"])
        self.storage = MemoryStorage()
        self.dp = Dispatcher(storage=self.storage)
        self.db = DatabaseService(self.config["database"]["url"])
        self.whois_checker = WhoisChecker()
        self.dns_checker = DNSChecker()
        self.scheduler = DomainCheckScheduler(
            self.db,
            self.whois_checker,
            self.dns_checker,
            self.send_notification,
        )

        # Регистрация обработчиков
        self._register_handlers()

    def _register_handlers(self):
        """Регистрация обработчиков команд."""
        self.dp.message.register(self.cmd_start, Command("start"))
        self.dp.message.register(self.cmd_help, Command("help"))
        self.dp.message.register(self.cmd_add, Command("add"))
        self.dp.message.register(self.cmd_list, Command("list"))
        self.dp.message.register(self.cmd_delete, Command("delete"))
        self.dp.message.register(self.cmd_status, Command("status"))
        self.dp.message.register(self.cmd_cancel, Command("cancel"))
        
        # Обработчики состояний
        self.dp.message.register(
            self.process_domain_name,
            DomainForm.waiting_for_domain,
        )
        self.dp.message.register(
            self.process_check_interval,
            DomainForm.waiting_for_interval,
        )
        
        # Обработчики callback-запросов
        self.dp.callback_query.register(self.process_domain_delete, lambda c: c.data.startswith("delete_"))
        self.dp.callback_query.register(self.process_domain_details, lambda c: c.data.startswith("details_"))
        self.dp.callback_query.register(self.process_domain_dns, lambda c: c.data.startswith("dns_"))
        self.dp.callback_query.register(self.process_domain_whois, lambda c: c.data.startswith("whois_"))
        self.dp.callback_query.register(self.process_back_to_list, lambda c: c.data == "back_to_list")

    async def send_notification(self, chat_id: int, message: str):
        """
        Отправка уведомления пользователю.

        Args:
            chat_id: ID чата
            message: Текст сообщения
        """
        await self.bot.send_message(
            chat_id=chat_id,
            text=message,
            parse_mode="Markdown",
        )

    async def cmd_start(self, message: types.Message):
        """Обработчик команды /start."""
        await message.answer(
            "👋 Привет! Я бот для мониторинга изменений в WHOIS и DNS записях доменов.\n\n"
            "Доступные команды:\n"
            "/add - Добавить домен для отслеживания\n"
            "/list - Показать список отслеживаемых доменов\n"
            "/delete - Удалить домен из отслеживания\n"
            "/status - Проверить текущий статус доменов\n"
            "/help - Показать справку\n"
            "/cancel - Отменить текущую операцию"
        )

    async def cmd_help(self, message: types.Message):
        """Обработчик команды /help."""
        await message.answer(
            "📖 *Справка по использованию бота*\n\n"
            "*Основные команды:*\n"
            "• /add - Добавить новый домен для отслеживания\n"
            "• /list - Показать список всех отслеживаемых доменов\n"
            "• /delete - Удалить домен из списка отслеживания\n"
            "• /status - Проверить текущий статус всех доменов\n"
            "• /cancel - Отменить текущую операцию\n\n"
            "*Как это работает:*\n"
            "1. Добавьте домен через команду /add\n"
            "2. Выберите интервал проверки\n"
            "3. Бот будет автоматически проверять изменения\n"
            "4. При обнаружении изменений вы получите уведомление\n\n"
            "*Примечания:*\n"
            "• Поддерживаются все публичные домены\n"
            "• Минимальный интервал проверки - 1 час\n"
            "• Можно отслеживать несколько доменов одновременно",
            parse_mode="Markdown",
        )

    async def cmd_add(self, message: types.Message, state: FSMContext):
        """Обработчик команды /add."""
        await state.set_state(DomainForm.waiting_for_domain)
        await message.answer(
            "Введите доменное имя для отслеживания (например, example.com):"
        )

    async def process_domain_name(self, message: types.Message, state: FSMContext):
        """Обработка введенного доменного имени."""
        domain = message.text.lower()
        
        if not is_valid_domain(domain):
            await message.answer(
                "❌ Некорректное доменное имя. Попробуйте еще раз:"
            )
            return

        # Проверяем, не отслеживается ли уже домен
        existing_domain = await self.db.get_domain_by_name(domain)
        if existing_domain:
            await message.answer(
                "❌ Этот домен уже отслеживается. "
                "Используйте /list для просмотра списка доменов."
            )
            await state.clear()
            return

        await state.update_data(domain_name=domain)
        await state.set_state(DomainForm.waiting_for_interval)
        
        keyboard = types.ReplyKeyboardMarkup(
            keyboard=[
                [
                    types.KeyboardButton(text="1 час"),
                    types.KeyboardButton(text="6 часов"),
                ],
                [
                    types.KeyboardButton(text="12 часов"),
                    types.KeyboardButton(text="24 часа"),
                ],
            ],
            resize_keyboard=True,
            one_time_keyboard=True,
        )
        
        await message.answer(
            "Выберите интервал проверки:",
            reply_markup=keyboard,
        )

    async def process_check_interval(self, message: types.Message, state: FSMContext):
        """Обработка выбранного интервала проверки."""
        intervals = {
            "1 час": 3600,
            "6 часов": 21600,
            "12 часов": 43200,
            "24 часа": 86400,
        }
        
        if message.text not in intervals:
            await message.answer(
                "❌ Пожалуйста, выберите интервал из предложенных вариантов."
            )
            return

        interval = intervals[message.text]
        data = await state.get_data()
        domain_name = data["domain_name"]

        # Создаем запись в БД
        domain = await self.db.create_domain(
            name=domain_name,
            chat_id=message.chat.id,
            check_interval=interval,
        )

        # Добавляем домен в планировщик
        await self.scheduler.add_domain(domain)

        await message.answer(
            f"✅ Домен {domain_name} добавлен для отслеживания.\n"
            f"Интервал проверки: {message.text}",
            reply_markup=types.ReplyKeyboardRemove(),
        )
        await state.clear()

    async def cmd_list(self, message: types.Message):
        """Обработчик команды /list."""
        domains = await self.db.get_domains_by_chat(message.chat.id)
        
        if not domains:
            await message.answer(
                "📝 У вас нет отслеживаемых доменов.\n"
                "Используйте /add чтобы добавить домен."
            )
            return

        response = ["📝 *Список отслеживаемых доменов:*\n"]
        for domain in domains:
            interval_hours = domain.check_interval / 3600
            response.append(
                f"• {domain.name}\n"
                f"  └ Интервал проверки: {interval_hours:.0f} ч."
            )

        await message.answer(
            "\n".join(response),
            parse_mode="Markdown",
        )

    async def cmd_delete(self, message: types.Message):
        """Обработчик команды /delete."""
        domains = await self.db.get_domains_by_chat(message.chat.id)
        
        if not domains:
            await message.answer(
                "📝 У вас нет отслеживаемых доменов.\n"
                "Используйте /add чтобы добавить домен."
            )
            return

        keyboard = types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text=domain.name,
                        callback_data=f"delete_{domain.id}",
                    )
                ]
                for domain in domains
            ]
        )

        await message.answer(
            "Выберите домен для удаления:",
            reply_markup=keyboard,
        )
        
    async def process_domain_delete(self, callback_query: types.CallbackQuery):
        """Обработчик удаления домена."""
        domain_id = int(callback_query.data.split("_")[1])
        
        # Получаем информацию о домене
        domain = await self.db.get_domain_by_id(domain_id)
        if not domain:
            await callback_query.answer("Домен не найден")
            return
        
        # Удаляем домен из планировщика и БД
        await self.scheduler.remove_domain(domain_id)
        await self.db.delete_domain(domain_id)
        
        await callback_query.answer(f"Домен {domain.name} удален из отслеживания")
        await callback_query.message.edit_text(f"✅ Домен {domain.name} удален из отслеживания")

    async def cmd_status(self, message: types.Message):
        """Обработчик команды /status."""
        domains = await self.db.get_domains_by_chat(message.chat.id)
        
        if not domains:
            await message.answer(
                "📝 У вас нет отслеживаемых доменов.\n"
                "Используйте /add чтобы добавить домен."
            )
            return

        # Создаем клавиатуру с кнопками для каждого домена
        keyboard = types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text=domain.name,
                        callback_data=f"details_{domain.id}",
                    )
                ]
                for domain in domains
            ]
        )

        await message.answer(
            "📊 *Выберите домен для просмотра подробной информации:*",
            parse_mode="Markdown",
            reply_markup=keyboard,
        )
        
    async def process_domain_details(self, callback_query: types.CallbackQuery):
        """Обработчик просмотра детальной информации о домене."""
        domain_id = int(callback_query.data.split("_")[1])
        
        # Получаем информацию о домене
        domain = await self.db.get_domain_by_id(domain_id)
        if not domain:
            await callback_query.answer("Домен не найден")
            return
        
        # Получаем последнюю WHOIS запись
        whois = await self.db.get_last_whois_record(domain_id)
        
        # Формируем базовую информацию о домене
        if whois:
            last_check = whois.created_at.strftime("%d.%m.%Y %H:%M:%S")
            
            # Проверяем статус домена
            if isinstance(whois.status, list) and whois.status:
                status = "✅ Активен"
            elif isinstance(whois.status, str) and whois.status:
                status = "✅ Активен"
            else:
                status = "❌ Неактивен"
                
            # Форматируем сроки регистрации
            expiration_date = (
                whois.expiration_date.strftime("%d.%m.%Y")
                if whois.expiration_date
                else "Нет данных"
            )
        else:
            last_check = "Нет данных"
            status = "❓ Неизвестно"
            expiration_date = "Нет данных"
        
        # Создаем клавиатуру с кнопками для просмотра WHOIS и DNS
        keyboard = types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text="📝 WHOIS информация",
                        callback_data=f"whois_{domain_id}",
                    )
                ],
                [
                    types.InlineKeyboardButton(
                        text="🌐 DNS записи",
                        callback_data=f"dns_{domain_id}",
                    )
                ],
                [
                    types.InlineKeyboardButton(
                        text="« Назад к списку",
                        callback_data="back_to_list",
                    )
                ],
            ]
        )
        
        # Формируем сообщение с основной информацией
        message_text = (
            f"📋 *Информация о домене {domain.name}*\n\n"
            f"Статус: {status}\n"
            f"Срок регистрации до: {expiration_date}\n"
            f"Интервал проверки: {domain.check_interval // 3600} ч.\n"
            f"Последняя проверка: {last_check}\n\n"
            f"Выберите тип информации для просмотра:"
        )
        
        await callback_query.message.edit_text(
            message_text,
            parse_mode="Markdown",
            reply_markup=keyboard,
        )
        await callback_query.answer()
        
    async def process_domain_whois(self, callback_query: types.CallbackQuery):
        """Обработчик просмотра WHOIS информации."""
        domain_id = int(callback_query.data.split("_")[1])
        
        # Получаем информацию о домене
        domain = await self.db.get_domain_by_id(domain_id)
        if not domain:
            await callback_query.answer("Домен не найден")
            return
        
        # Получаем последнюю WHOIS запись
        whois_record = await self.db.get_last_whois_record(domain_id)
        
        if whois_record:
            # Формируем сообщение с WHOIS информацией
            whois_info = [f"📄 *WHOIS-информация для домена: {domain.name}*\n"]
            
            # Регистратор
            if whois_record.registrar:
                whois_info.append(f"🏢 *Регистратор:* {whois_record.registrar}")
                if whois_record.registrar_url:
                    whois_info.append(f"🔗 {whois_record.registrar_url}")
                whois_info.append("")
            
            # Статус
            if whois_record.status:
                status_list = json.loads(whois_record.status) if isinstance(whois_record.status, str) else whois_record.status
                if status_list:
                    whois_info.append("📌 *Статус:*")
                    for status in status_list:
                        whois_info.append(f"• {status}")
                    # Добавляем ссылки на описания статусов
                    for status in status_list:
                        if "clientTransferProhibited" in status:
                            whois_info.append("🔗 https://icann.org/epp#clientTransferProhibited")
                        elif "pendingDelete" in status:
                            whois_info.append("🔗 https://icann.org/epp#pendingDelete")
                    whois_info.append("")
            
            # Даты
            dates_info = []
            if whois_record.creation_date:
                dates_info.append(f"• Создан: {whois_record.creation_date.strftime('%d.%m.%Y')}")
            if whois_record.last_updated:
                dates_info.append(f"• Обновлён: {whois_record.last_updated.strftime('%d.%m.%Y')}")
            if whois_record.expiration_date:
                dates_info.append(f"• Срок окончания: {whois_record.expiration_date.strftime('%d.%m.%Y')}")
            
            if dates_info:
                whois_info.append("📅 *Даты:*")
                whois_info.extend(dates_info)
                whois_info.append("")
            
            # Контактная информация
            whois_info.append(f"🧾 *Владелец:* {whois_record.owner or '—'}")
            whois_info.append(f"👤 *Админ. контакт:* {whois_record.admin_contact or '—'}")
            whois_info.append(f"🛠️ *Тех. контакт:* {whois_record.tech_contact or '—'}")
            whois_info.append("")
            
            # Серверы имен
            if whois_record.name_servers:
                ns_list = json.loads(whois_record.name_servers) if isinstance(whois_record.name_servers, str) else whois_record.name_servers
                if ns_list:
                    whois_info.append("🛰 *NS-серверы:*")
                    for ns in ns_list:
                        whois_info.append(f"• {ns}")
                    whois_info.append("")
            
            # Дополнительная информация
            whois_info.append(f"🔍 *WHOIS-сервер:* {whois_record.whois_server or '—'}")
            whois_info.append(f"🔐 *DNSSEC:* {whois_record.dnssec or 'unsigned'}")
            whois_info.append("")
            
            # Время проверки
            if hasattr(whois_record, 'created_at') and whois_record.created_at:
                whois_info.append(f"🕒 *Последняя проверка:* {whois_record.created_at.strftime('%d.%m.%Y %H:%M:%S')}")
        else:
            whois_info = [
                f"📄 *WHOIS-информация для домена {domain.name}*\n",
                "Нет данных WHOIS. Возможно, домен еще не проверялся."
            ]
        
        # Создаем кнопку "Назад"
        keyboard = types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text="« Назад к информации о домене",
                        callback_data=f"details_{domain_id}",
                    )
                ],
            ]
        )
        
        # Отправляем сообщение
        await callback_query.message.edit_text(
            "\n".join(whois_info),
            parse_mode="Markdown",
            reply_markup=keyboard,
        )
        await callback_query.answer()
        
    async def process_domain_dns(self, callback_query: types.CallbackQuery):
        """Обработчик просмотра DNS записей."""
        domain_id = int(callback_query.data.split("_")[1])
        
        # Получаем информацию о домене
        domain = await self.db.get_domain_by_id(domain_id)
        if not domain:
            await callback_query.answer("Домен не найден")
            return
        
        logger.info(f"Запрошены DNS записи для домена {domain.name} (ID: {domain_id})")
        
        # Напрямую получаем DNS записи из базы данных для отладки
        async with self.db.async_session() as session:
            from sqlalchemy import select, desc
            from src.db.models import DNSRecord
            
            # Получаем последние записи для каждого типа
            query = select(DNSRecord).where(DNSRecord.domain_id == domain_id).order_by(desc(DNSRecord.created_at))
            result = await session.execute(query)
            all_records = result.scalars().all()
            
            # Группируем записи по типу, оставляя только самые свежие
            latest_records = {}
            for record in all_records:
                if record.record_type not in latest_records:
                    latest_records[record.record_type] = record
            
            logger.debug(f"Найдено {len(latest_records)} уникальных типов DNS записей")
            
            # Формируем сообщение с DNS записями в новом формате
            dns_info = [f"🌐 *DNS-записи для домена: {domain.name}*\n"]
            
            # Стандартные типы DNS записей, которые мы всегда хотим показать
            standard_record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME", "PTR", "SRV"]
            
            # Иконки для разных типов записей
            record_icons = {
                "A": "📍",
                "AAAA": "📍",
                "MX": "📬",
                "NS": "🔒",
                "SOA": "📄",
                "TXT": "📥",
                "CNAME": "🔁",
                "PTR": "📌",
                "SRV": "📦"
            }
            
            # Названия для разных типов записей
            record_names = {
                "A": "A-запись",
                "AAAA": "AAAA-запись",
                "MX": "MX-записи",
                "NS": "NS-серверы",
                "SOA": "SOA-запись",
                "TXT": "TXT-записи",
                "CNAME": "CNAME",
                "PTR": "PTR",
                "SRV": "SRV"
            }
            
            # Объединяем стандартные типы и имеющиеся типы
            all_record_types = list(set(standard_record_types) | set(latest_records.keys()))
            all_record_types.sort()  # Сортируем для единообразия отображения
            
            for record_type in all_record_types:
                icon = record_icons.get(record_type, "🔹")
                name = record_names.get(record_type, f"{record_type}-запись")
                
                if record_type in latest_records:
                    record = latest_records[record_type]
                    try:
                        import json
                        values = json.loads(record.values)
                        ttl = record.ttl if record.ttl else "Нет данных"
                        
                        logger.debug(f"Обработка записи {record_type}: {values}, TTL={ttl}")
                        
                        dns_info.append(f"{icon} *{name}:*")
                        if values:
                            for value in values:
                                # Экранируем специальные символы Markdown
                                escaped_value = value.replace("_", "\\_").replace("*", "\\*").replace("[", "\\[").replace("`", "\\`")
                                dns_info.append(f"• {escaped_value} (TTL: {ttl})")
                            dns_info.append("")
                        else:
                            dns_info.append("• ❌ Нет данных\n")
                    except Exception as e:
                        logger.error(f"Ошибка при обработке записи {record_type}: {e}")
                        dns_info.append(f"{icon} *{name}:*")
                        dns_info.append(f"• ⚠️ Ошибка обработки: {e}\n")
                else:
                    logger.debug(f"Запись {record_type} не найдена")
                    # Показываем отсутствующие типы записей
                    dns_info.append(f"{icon} *{name}:*")
                    dns_info.append("• ❌ Не найдена\n")
            
            # Получаем текущее время для отображения времени проверки
            current_time = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
            dns_info.append(f"🕒 *Последняя проверка:* {current_time}")
            
            # Создаем кнопку "Назад"
            keyboard = types.InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        types.InlineKeyboardButton(
                            text="« Назад к информации о домене",
                            callback_data=f"details_{domain_id}",
                        )
                    ],
                ]
            )
            
            try:
                # Отправляем сообщение
                await callback_query.message.edit_text(
                    "\n".join(dns_info),
                    parse_mode="Markdown",
                    reply_markup=keyboard,
                )
            except Exception as e:
                logger.error(f"Ошибка при отображении DNS записей: {e}")
                # Если возникла ошибка форматирования, отправляем без форматирования
                await callback_query.message.edit_text(
                    f"DNS записи для домена {domain.name}\n\n" + 
                    "Не удалось отобразить записи в форматированном виде.\n" +
                    "Используйте команду /status для просмотра информации о домене.",
                    reply_markup=keyboard,
                )
            
            await callback_query.answer()
        
    async def process_back_to_list(self, callback_query: types.CallbackQuery):
        """Обработчик возврата к списку доменов."""
        # Получаем список доменов пользователя
        domains = await self.db.get_domains_by_chat(callback_query.from_user.id)
        
        if not domains:
            await callback_query.message.edit_text(
                "📝 У вас нет отслеживаемых доменов.\n"
                "Используйте /add чтобы добавить домен."
            )
            await callback_query.answer()
            return
        
        # Создаем клавиатуру с кнопками для каждого домена
        keyboard = types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text=domain.name,
                        callback_data=f"details_{domain.id}",
                    )
                ]
                for domain in domains
            ]
        )
        
        await callback_query.message.edit_text(
            "📊 *Выберите домен для просмотра подробной информации:*",
            parse_mode="Markdown",
            reply_markup=keyboard,
        )
        await callback_query.answer()

    async def cmd_cancel(self, message: types.Message, state: FSMContext):
        """Обработчик команды /cancel."""
        current_state = await state.get_state()
        
        if current_state is None:
            await message.answer(
                "🤔 Нечего отменять. Используйте /help для просмотра команд."
            )
            return

        await state.clear()
        await message.answer(
            "✅ Операция отменена.",
            reply_markup=types.ReplyKeyboardRemove(),
        )

    async def start(self):
        """Запуск бота."""
        logger.info("Запуск бота...")
        
        # Инициализируем базу данных
        await self.db.init_db()
        
        # Запускаем планировщик
        await self.scheduler.start()
        
        # Запускаем бота
        await self.dp.start_polling(self.bot)

    async def stop(self):
        """Остановка бота."""
        logger.info("Остановка бота...")
        
        # Останавливаем планировщик
        await self.scheduler.stop()
        
        # Закрываем соединение с БД
        await self.db.close()


async def main():
    """Точка входа."""
    bot = WhoisCheckerBot()
    
    try:
        await bot.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Получен сигнал завершения...")
    finally:
        await bot.stop()


if __name__ == "__main__":
    asyncio.run(main()) 