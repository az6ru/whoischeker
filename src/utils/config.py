"""Модуль для работы с конфигурацией."""

import logging
import os
from pathlib import Path
from typing import Any, Dict

import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Загружаем .env файл, если он существует
load_dotenv()

# Путь к конфигурационному файлу
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "config/config.yml"))


def load_config() -> Dict[str, Any]:
    """
    Загрузка конфигурации из файла с поддержкой переменных окружения.

    Returns:
        Dict[str, Any]: Словарь с конфигурацией
    """
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Конфигурационный файл не найден: {CONFIG_PATH}. "
            "Скопируйте config.example.yml в config.yml и настройте его."
        )

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"Ошибка при чтении конфигурационного файла: {e}")

    # Проверяем обязательные параметры
    required_sections = ["bot", "database", "monitoring", "logging"]
    for section in required_sections:
        if section not in config:
            raise ValueError(f"В конфигурации отсутствует обязательная секция: {section}")

    # Применяем переменные окружения
    # Telegram бот токен
    if telegram_token := os.environ.get("TELEGRAM_BOT_TOKEN"):
        config["bot"]["token"] = telegram_token
    
    # Список администраторов (разделенных запятыми)
    if admins := os.environ.get("TELEGRAM_ADMINS"):
        config["bot"]["admins"] = [int(admin.strip()) for admin in admins.split(",") if admin.strip()]
    
    # URL базы данных
    if db_url := os.environ.get("DATABASE_URL"):
        config["database"]["url"] = db_url
    
    # Настройки логирования
    if log_level := os.environ.get("LOG_LEVEL"):
        config["logging"]["level"] = log_level
    
    if log_file := os.environ.get("LOG_FILE"):
        config["logging"]["file"] = log_file

    # Создаем необходимые директории
    log_dir = Path(config["logging"]["file"]).parent
    data_dir = Path(config["database"]["url"].split("///")[-1]).parent
    
    log_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    return config