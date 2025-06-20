"""Основной модуль Telegram бота."""

import asyncio
import logging
from typing import Dict, Optional

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
    level=logging.INFO,
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

    async def cmd_status(self, message: types.Message):
        """Обработчик команды /status."""
        domains = await self.db.get_domains_by_chat(message.chat.id)
        
        if not domains:
            await message.answer(
                "📝 У вас нет отслеживаемых доменов.\n"
                "Используйте /add чтобы добавить домен."
            )
            return

        status_message = ["📊 *Статус отслеживаемых доменов:*\n"]
        
        for domain in domains:
            # Получаем последние записи
            whois = await self.db.get_last_whois_record(domain.id)
            
            if whois:
                last_check = whois.created_at.strftime("%d.%m.%Y %H:%M:%S")
                # Проверяем статус домена
                if isinstance(whois.status, list) and whois.status:
                    status = "✅ Активен"
                    status_details = ", ".join(whois.status)
                elif isinstance(whois.status, str) and whois.status:
                    status = "✅ Активен"
                    status_details = whois.status
                else:
                    status = "❌ Неактивен"
                    status_details = "Нет данных о статусе"
                
                expiration = (
                    whois.expiration_date.strftime("%d.%m.%Y")
                    if whois.expiration_date
                    else "Нет данных"
                )
            else:
                last_check = "Нет данных"
                status = "❓ Неизвестно"
                status_details = "Нет данных"
                expiration = "Нет данных"

            status_message.extend([
                f"• *{domain.name}*",
                f"  └ Статус: {status}",
                f"  └ Детали статуса: {status_details}",
                f"  └ Срок регистрации до: {expiration}",
                f"  └ Последняя проверка: {last_check}\n",
            ])

        await message.answer(
            "\n".join(status_message),
            parse_mode="Markdown",
        )

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