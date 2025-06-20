"""Модуль для работы с DNS-записями доменов."""

import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

import dns.resolver
from dns.resolver import Answer, NoAnswer, NXDOMAIN


@dataclass
class DNSRecord:
    """Структура для хранения DNS-записи."""

    record_type: str
    values: List[str]
    ttl: int


class DNSInfo:
    """Класс для хранения DNS-информации домена."""

    def __init__(self, domain: str) -> None:
        """
        Инициализация объекта DNS-информации.

        Args:
            domain: Доменное имя
        """
        self.domain = domain
        self.records: Dict[str, DNSRecord] = {}

    def add_record(self, record_type: str, values: List[str], ttl: int) -> None:
        """
        Добавление DNS-записи.

        Args:
            record_type: Тип записи (A, AAAA, MX, etc.)
            values: Список значений записи
            ttl: Time To Live
        """
        self.records[record_type] = DNSRecord(record_type, values, ttl)

    def to_dict(self) -> Dict[str, any]:
        """
        Преобразование объекта в словарь.

        Returns:
            Dict[str, any]: Словарь с DNS-информацией
        """
        return {
            "domain": self.domain,
            "records": {
                rtype: {
                    "values": record.values,
                    "ttl": record.ttl,
                }
                for rtype, record in self.records.items()
            },
        }


class DNSChecker:
    """Класс для проверки DNS-записей доменов."""

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: int = 10,
        record_types: Optional[List[str]] = None,
    ) -> None:
        """
        Инициализация checker'а.

        Args:
            nameservers: Список DNS-серверов
            timeout: Таймаут запросов в секундах
            record_types: Список типов записей для проверки
        """
        self.resolver = dns.resolver.Resolver()
        
        if nameservers:
            self.resolver.nameservers = nameservers
            
        self.resolver.timeout = timeout
        self.record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    async def _query_record(
        self, domain: str, record_type: str
    ) -> Union[Answer, NoAnswer, NXDOMAIN, None]:
        """
        Выполнение DNS-запроса.

        Args:
            domain: Доменное имя
            record_type: Тип записи

        Returns:
            Union[Answer, NoAnswer, NXDOMAIN, None]: Результат запроса
        """
        try:
            # Выполняем DNS-запрос в отдельном потоке
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.resolver.resolve(domain, record_type)
            )
        except (NoAnswer, NXDOMAIN):
            return None
        except Exception:
            return None

    async def get_dns_info(self, domain: str) -> DNSInfo:
        """
        Получение DNS-информации для домена.

        Args:
            domain: Доменное имя

        Returns:
            DNSInfo: Объект с DNS-информацией
        """
        dns_info = DNSInfo(domain)

        for record_type in self.record_types:
            answer = await self._query_record(domain, record_type)
            if answer:
                values = [str(r) for r in answer]
                ttl = answer.ttl
                dns_info.add_record(record_type, values, ttl)

        return dns_info

    def compare_dns_info(
        self, old_info: DNSInfo, new_info: DNSInfo
    ) -> Dict[str, Dict[str, tuple[List[str], List[str]]]]:
        """
        Сравнение двух DNS-записей.

        Args:
            old_info: Старая DNS-информация
            new_info: Новая DNS-информация

        Returns:
            Dict[str, Dict[str, tuple[List[str], List[str]]]]: Словарь изменений
        """
        changes = {}

        # Проверяем удаленные записи
        for record_type in old_info.records:
            if record_type not in new_info.records:
                changes[record_type] = {
                    "values": (old_info.records[record_type].values, []),
                    "ttl": (old_info.records[record_type].ttl, 0),
                }

        # Проверяем новые и измененные записи
        for record_type, new_record in new_info.records.items():
            if record_type not in old_info.records:
                changes[record_type] = {
                    "values": ([], new_record.values),
                    "ttl": (0, new_record.ttl),
                }
            else:
                old_record = old_info.records[record_type]
                if (
                    old_record.values != new_record.values
                    or old_record.ttl != new_record.ttl
                ):
                    changes[record_type] = {
                        "values": (old_record.values, new_record.values),
                        "ttl": (old_record.ttl, new_record.ttl),
                    }

        return changes 