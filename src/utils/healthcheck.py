"""Модуль для проверки работоспособности бота."""

import asyncio
import logging
import sys
from pathlib import Path

# Добавляем корневую директорию в системный путь
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.dns_checker import DNSChecker
from src.core.whois_checker import WhoisChecker
from src.db.service import DatabaseService
from src.utils.config import load_config

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def check_database(config):
    """
    Проверяет подключение к базе данных.
    
    Args:
        config: Загруженная конфигурация
        
    Returns:
        bool: True, если проверка успешна, иначе False
    """
    try:
        db = DatabaseService(config["database"]["url"])
        await db.init_db()
        # Пытаемся выполнить простой запрос
        await db.get_all_domains()
        await db.close()
        logger.info("✅ Подключение к базе данных работает")
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка подключения к базе данных: {e}")
        return False


async def check_whois_service():
    """
    Проверяет работу WHOIS сервиса.
    
    Returns:
        bool: True, если проверка успешна, иначе False
    """
    try:
        whois_checker = WhoisChecker()
        test_domain = "example.com"
        whois_info = await whois_checker.get_whois_info(test_domain)
        if whois_info and whois_info.registrar:
            logger.info(
                f"✅ WHOIS сервис работает. "
                f"Регистратор для {test_domain}: {whois_info.registrar}"
            )
            return True
        else:
            logger.warning("⚠️ WHOIS сервис вернул неполные данные")
            return False
    except Exception as e:
        logger.error(f"❌ Ошибка WHOIS сервиса: {e}")
        return False


async def check_dns_service():
    """
    Проверяет работу DNS сервиса.
    
    Returns:
        bool: True, если проверка успешна, иначе False
    """
    try:
        dns_checker = DNSChecker()
        test_domain = "example.com"
        dns_info = await dns_checker.get_dns_info(test_domain)
        if dns_info and dns_info.records:
            logger.info(
                f"✅ DNS сервис работает. "
                f"Получены записи для {test_domain}: {list(dns_info.records.keys())}"
            )
            return True
        else:
            logger.warning("⚠️ DNS сервис вернул пустые данные")
            return False
    except Exception as e:
        logger.error(f"❌ Ошибка DNS сервиса: {e}")
        return False


async def run_healthcheck():
    """
    Запускает все проверки здоровья системы.
    
    Returns:
        int: 0 - если все проверки успешны, 1 - если есть ошибки
    """
    try:
        config = load_config()
        logger.info("📋 Начинаем проверку системы...")
        
        db_check = await check_database(config)
        whois_check = await check_whois_service()
        dns_check = await check_dns_service()
        
        all_ok = db_check and whois_check and dns_check
        
        if all_ok:
            logger.info("✅ Все сервисы работают корректно")
            return 0
        else:
            logger.error("❌ Некоторые проверки не пройдены")
            return 1
    except Exception as e:
        logger.critical(f"❌ Критическая ошибка при проверке: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_healthcheck())
    sys.exit(exit_code) 