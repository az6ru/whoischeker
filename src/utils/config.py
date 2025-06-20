"""Модуль для работы с конфигурацией."""

import logging
import os
from pathlib import Path
from typing import Any, Dict

import yaml

logger = logging.getLogger(__name__)

# Путь к конфигурационному файлу
CONFIG_PATH = Path("config/config.yml")


def load_config() -> Dict[str, Any]:
    """
    Загрузка конфигурации из файла.

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

    # Создаем необходимые директории
    log_dir = Path(config["logging"]["file"]).parent
    data_dir = Path(config["database"]["url"].split("///")[-1]).parent
    
    log_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    return config 