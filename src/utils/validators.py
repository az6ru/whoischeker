"""Модуль для валидации данных."""

import re
from typing import Tuple


def validate_domain_name(domain: str) -> Tuple[bool, str]:
    """
    Валидация доменного имени.

    Args:
        domain: Доменное имя для проверки

    Returns:
        Tuple[bool, str]: (результат валидации, сообщение об ошибке)
    """
    # Удаляем пробелы в начале и конце
    domain = domain.strip().lower()

    # Проверяем длину
    if len(domain) > 253:
        return False, "Доменное имя слишком длинное (максимум 253 символа)"
    if len(domain) < 3:
        return False, "Доменное имя слишком короткое (минимум 3 символа)"

    # Проверяем формат
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    if not re.match(pattern, domain):
        return False, "Неверный формат доменного имени"

    # Проверяем каждую метку (часть между точками)
    labels = domain.split(".")
    for label in labels:
        if len(label) > 63:
            return False, f"Метка '{label}' слишком длинная (максимум 63 символа)"
        if label.startswith("-") or label.endswith("-"):
            return False, f"Метка '{label}' не может начинаться или заканчиваться дефисом"
        if not all(c.isalnum() or c == "-" for c in label):
            return False, f"Метка '{label}' содержит недопустимые символы"

    return True, ""


def is_valid_domain(domain: str) -> bool:
    """
    Проверка валидности доменного имени.

    Args:
        domain: Доменное имя для проверки

    Returns:
        bool: True если домен валидный, False в противном случае
    """
    if not domain:
        return False

    # Максимальная длина домена - 253 символа
    if len(domain) > 253:
        return False

    # Паттерн для проверки доменного имени
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    try:
        return bool(re.match(pattern, domain))
    except re.error:
        return False 