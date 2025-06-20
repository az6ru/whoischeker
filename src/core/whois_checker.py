"""Модуль для работы с WHOIS-информацией доменов."""

import time
import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Union, List

import whois


@dataclass
class WhoisInfo:
    """Структура для хранения WHOIS-информации."""

    domain_name: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    name_servers: Optional[list[str]] = None
    status: Optional[list[str]] = None
    emails: Optional[list[str]] = None
    raw: Optional[str] = None
    created_at: Optional[datetime] = None  # Время создания записи в БД

    @classmethod
    def from_whois_dict(cls, domain: str, entry: Dict) -> "WhoisInfo":
        """
        Создание объекта WhoisInfo из результата whois.whois().

        Args:
            domain: Доменное имя
            entry: Словарь с WHOIS-информацией

        Returns:
            WhoisInfo: Объект с WHOIS-информацией
        """
        # Обработка даты создания
        creation_date = entry.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        
        # Обработка даты истечения
        expiration_date = entry.get('expiration_date')
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0] if expiration_date else None
        
        # Обработка даты обновления
        updated_date = entry.get('updated_date')
        if isinstance(updated_date, list):
            updated_date = updated_date[0] if updated_date else None

        # Обработка серверов имен
        name_servers = entry.get('name_servers', [])
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif isinstance(name_servers, (list, tuple)):
            name_servers = list(name_servers)
        else:
            name_servers = []

        # Обработка статусов
        status = entry.get('status', [])
        if isinstance(status, str):
            status = [status]
        elif isinstance(status, (list, tuple)):
            status = list(status)
        else:
            status = []

        return cls(
            domain_name=domain,
            registrar=entry.get('registrar'),
            creation_date=creation_date,
            expiration_date=expiration_date,
            last_updated=updated_date,
            name_servers=name_servers,
            status=status,
            emails=entry.get('emails', []),
            raw=str(entry),
            created_at=datetime.now(),
        )

    def to_dict(self) -> Dict[str, any]:
        """
        Преобразование объекта в словарь.

        Returns:
            Dict[str, any]: Словарь с WHOIS-информацией
        """
        return {
            "domain_name": self.domain_name,
            "registrar": self.registrar,
            "creation_date": self.creation_date.isoformat() if self.creation_date else None,
            "expiration_date": self.expiration_date.isoformat() if self.expiration_date else None,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "name_servers": self.name_servers,
            "status": self.status,
            "emails": self.emails,
            "raw": self.raw,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WhoisChecker:
    """Класс для проверки WHOIS-информации доменов."""

    def __init__(
        self, timeout: int = 30, retry_count: int = 3, retry_delay: int = 5
    ) -> None:
        """
        Инициализация checker'а.

        Args:
            timeout: Таймаут запросов в секундах
            retry_count: Количество попыток при ошибке
            retry_delay: Задержка между попытками в секундах
        """
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay

    async def get_whois_info(self, domain: str) -> WhoisInfo:
        """
        Получение WHOIS-информации для домена.

        Args:
            domain: Доменное имя

        Returns:
            WhoisInfo: Объект с WHOIS-информацией

        Raises:
            Exception: При ошибке получения информации
        """
        attempts = 0
        last_error = None

        while attempts < self.retry_count:
            try:
                # Выполняем whois запрос в отдельном потоке, чтобы не блокировать event loop
                entry = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: whois.whois(domain)
                )
                if entry is None or not entry.get('domain_name'):
                    raise ValueError(f"Не удалось получить WHOIS для домена {domain}")
                return WhoisInfo.from_whois_dict(domain, entry)
            except Exception as e:
                last_error = e
                attempts += 1
                if attempts < self.retry_count:
                    await asyncio.sleep(self.retry_delay)

        raise Exception(
            f"Не удалось получить WHOIS-информацию после {self.retry_count} попыток"
        ) from last_error

    def compare_whois_info(
        self, old_info: WhoisInfo, new_info: WhoisInfo
    ) -> Dict[str, tuple[any, any]]:
        """
        Сравнение двух WHOIS-записей.

        Args:
            old_info: Старая WHOIS-информация
            new_info: Новая WHOIS-информация

        Returns:
            Dict[str, tuple[any, any]]: Словарь изменений в формате {поле: (старое_значение, новое_значение)}
        """
        changes = {}
        fields = [
            "registrar",
            "creation_date",
            "expiration_date",
            "last_updated",
            "name_servers",
            "status",
            "emails",
        ]

        for field in fields:
            old_value = getattr(old_info, field)
            new_value = getattr(new_info, field)

            if old_value != new_value:
                changes[field] = (old_value, new_value)

        return changes 