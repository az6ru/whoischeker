"""Модуль для сравнения изменений в WHOIS и DNS записях."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from src.core.whois_checker import WhoisInfo
from src.core.dns_checker import DNSInfo
from src.db.models import Domain


@dataclass
class WhoisChange:
    """Изменение в WHOIS записи."""
    field: str
    old_value: str
    new_value: str


@dataclass
class DNSChange:
    """Изменение в DNS записи."""
    record_type: str
    old_values: List[str]
    new_values: List[str]


@dataclass
class DomainChanges:
    """Изменения в домене."""
    domain: Domain
    whois_changes: List[WhoisChange]
    dns_changes: List[DNSChange]
    check_time: datetime


def compare_whois_records(
    old_record: Optional[WhoisInfo],
    new_record: WhoisInfo,
) -> List[WhoisChange]:
    """
    Сравнение WHOIS записей.

    Args:
        old_record: Предыдущая WHOIS запись
        new_record: Новая WHOIS запись

    Returns:
        List[WhoisChange]: Список изменений
    """
    changes = []
    
    # Если это первая проверка
    if not old_record:
        return []

    # Поля для сравнения и их человекочитаемые названия
    fields_to_compare = {
        "registrar": "Регистратор",
        "creation_date": "Дата создания",
        "expiration_date": "Дата истечения",
        "last_updated": "Дата обновления",
        "status": "Статус",
        "name_servers": "Серверы имен",
    }

    for field, display_name in fields_to_compare.items():
        old_value = getattr(old_record, field)
        new_value = getattr(new_record, field)

        # Пропускаем None значения
        if old_value is None and new_value is None:
            continue

        # Для списков (например, name_servers)
        if isinstance(old_value, (list, tuple)) or isinstance(new_value, (list, tuple)):
            old_set = set(old_value) if old_value else set()
            new_set = set(new_value) if new_value else set()
            if old_set != new_set:
                changes.append(
                    WhoisChange(
                        field=display_name,
                        old_value=", ".join(sorted(old_set)) if old_set else "(пусто)",
                        new_value=", ".join(sorted(new_set)) if new_set else "(пусто)",
                    )
                )
        # Для дат
        elif isinstance(old_value, datetime) or isinstance(new_value, datetime):
            old_str = old_value.strftime("%d.%m.%Y %H:%M:%S") if old_value else "(не указано)"
            new_str = new_value.strftime("%d.%m.%Y %H:%M:%S") if new_value else "(не указано)"
            if old_str != new_str:
                changes.append(
                    WhoisChange(
                        field=display_name,
                        old_value=old_str,
                        new_value=new_str,
                    )
                )
        # Для остальных типов
        elif old_value != new_value:
            changes.append(
                WhoisChange(
                    field=display_name,
                    old_value=str(old_value) if old_value is not None else "(не указано)",
                    new_value=str(new_value) if new_value is not None else "(не указано)",
                )
            )

    return changes


def compare_dns_records(
    old_info: Optional[DNSInfo],
    new_info: DNSInfo,
) -> List[DNSChange]:
    """
    Сравнение DNS записей.

    Args:
        old_info: Старая DNS информация
        new_info: Новая DNS информация

    Returns:
        List[DNSChange]: Список изменений
    """
    changes = []

    # Если это первая проверка
    if not old_info:
        return []

    # Сравниваем записи каждого типа
    all_types = set(old_info.records.keys()) | set(new_info.records.keys())
    for record_type in all_types:
        old_record = old_info.records.get(record_type)
        new_record = new_info.records.get(record_type)

        old_values = set(old_record.values) if old_record else set()
        new_values = set(new_record.values) if new_record else set()

        if old_values != new_values:
            changes.append(
                DNSChange(
                    record_type=record_type,
                    old_values=sorted(old_values) if old_values else [],
                    new_values=sorted(new_values) if new_values else [],
                )
            )

    return changes


def format_changes_message(changes: DomainChanges) -> str:
    """
    Форматирование сообщения об изменениях.

    Args:
        changes: Объект с изменениями

    Returns:
        str: Отформатированное сообщение
    """
    lines = [
        f"🔔 Обнаружены изменения для домена *{changes.domain.name}*\n"
        f"_Время проверки: {changes.check_time.strftime('%d.%m.%Y %H:%M:%S')}_\n"
    ]

    # Форматируем WHOIS изменения
    if changes.whois_changes:
        lines.append("\n📝 *Изменения в WHOIS:*")
        for change in changes.whois_changes:
            lines.append(
                f"• {change.field}:\n"
                f"  - Было: {change.old_value}\n"
                f"  - Стало: {change.new_value}"
            )

    # Форматируем DNS изменения
    if changes.dns_changes:
        lines.append("\n🌐 *Изменения в DNS записях:*")
        for change in changes.dns_changes:
            lines.append(
                f"• Запись {change.record_type}:\n"
                f"  - Было: {', '.join(change.old_values) if change.old_values else '(пусто)'}\n"
                f"  - Стало: {', '.join(change.new_values) if change.new_values else '(пусто)'}"
            )

    return "\n".join(lines) 