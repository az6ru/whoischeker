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
        "registrar_url": "URL регистратора",
        "creation_date": "Дата создания",
        "expiration_date": "Дата истечения",
        "last_updated": "Дата обновления",
        "status": "Статус",
        "name_servers": "Серверы имен",
        "emails": "Email контакты",
        "owner": "Владелец",
        "admin_contact": "Административный контакт",
        "tech_contact": "Технический контакт",
        "address": "Адрес",
        "phone": "Телефон",
        "dnssec": "DNSSEC",
        "whois_server": "WHOIS сервер",
    }

    for field, display_name in fields_to_compare.items():
        old_value = getattr(old_record, field)
        new_value = getattr(new_record, field)

        # Пропускаем None значения, только если оба значения None
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
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Первая проверка DNS записей, изменения не фиксируются")
        return []

    # Сравниваем записи каждого типа
    all_types = set(old_info.records.keys()) | set(new_info.records.keys())
    
    import logging
    logger = logging.getLogger(__name__)
    logger.debug(f"Сравнение DNS записей: старые типы: {set(old_info.records.keys())}, новые типы: {set(new_info.records.keys())}")
    
    for record_type in all_types:
        old_record = old_info.records.get(record_type)
        new_record = new_info.records.get(record_type)

        # Если записи нет ни в старых, ни в новых данных, пропускаем
        if not old_record and not new_record:
            logger.debug(f"Тип записи {record_type}: пропускается, т.к. отсутствует в обоих наборах")
            continue
            
        old_values = set(old_record.values) if old_record and hasattr(old_record, 'values') and old_record.values else set()
        new_values = set(new_record.values) if new_record and hasattr(new_record, 'values') and new_record.values else set()

        # Логируем значения для отладки
        logger.debug(f"Тип записи {record_type}: старые значения: {old_values}, новые значения: {new_values}")
        
        # Проверяем, действительно ли есть изменения
        if old_values != new_values:
            # Добавляем только если значения реально отличаются
            # и не являются пустыми множествами одновременно
            if not (not old_values and not new_values):
                logger.info(f"Обнаружено изменение в записи {record_type}: {old_values} -> {new_values}")
                changes.append(
                    DNSChange(
                        record_type=record_type,
                        old_values=sorted(old_values) if old_values else [],
                        new_values=sorted(new_values) if new_values else [],
                    )
                )
        else:
            logger.debug(f"Тип записи {record_type}: без изменений")

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
        f"🔔 *Обнаружены изменения в DNS-домене: {changes.domain.name}*\n"
        f"📅 *Время проверки:* {changes.check_time.strftime('%d.%m.%Y %H:%M:%S')}\n"
    ]

    # Добавляем заголовок для изменений, если они есть
    if changes.whois_changes or changes.dns_changes:
        lines.append("📌 *Изменения:*\n")

    # Форматируем WHOIS изменения
    if changes.whois_changes:
        lines.append("📄 *WHOIS-информация:*")
        for change in changes.whois_changes:
            # Специальная обработка для слишком длинных значений
            old_value = change.old_value
            new_value = change.new_value
            
            # Ограничиваем длину для слишком длинных значений
            if len(old_value) > 100:
                old_value = old_value[:97] + "..."
            if len(new_value) > 100:
                new_value = new_value[:97] + "..."
                
            lines.append(
                f"• *{change.field}*:\n"
                f"  Было: {old_value}\n"
                f"  Стало: {new_value}\n"
            )

    # Форматируем DNS изменения
    if changes.dns_changes:
        # Иконки для разных типов изменений
        change_icons = {
            "add": "🆕",
            "remove": "❌",
            "update": "✏️"
        }
        
        # Названия для разных типов записей
        record_names = {
            "A": "A-запись",
            "AAAA": "AAAA-запись",
            "MX": "MX-записи",
            "NS": "NS-записи",
            "SOA": "SOA-запись",
            "TXT": "TXT-запись",
            "CNAME": "CNAME-запись",
            "PTR": "PTR-запись",
            "SRV": "SRV-запись"
        }
        
        for change in changes.dns_changes:
            # Для DNS-записей определяем тип изменения
            if not change.old_values and change.new_values:
                change_type = "add"
                change_desc = "добавлена"
            elif change.old_values and not change.new_values:
                change_type = "remove"
                change_desc = "удалена"
            else:
                change_type = "update"
                change_desc = "обновлена"
                
            icon = change_icons.get(change_type, "🔄")
            name = record_names.get(change.record_type, f"{change.record_type}-запись")
            
            lines.append(
                f"{icon} *{name} {change_desc}:*"
            )
            
            # Форматируем старые значения
            if change.old_values:
                lines.append("  Было:")
                for value in change.old_values:
                    lines.append(f"  • {value}")
            else:
                lines.append("  Было: —")
            
            # Форматируем новые значения
            if change.new_values:
                lines.append("  Стало:")
                for value in change.new_values:
                    # Для TXT записей с идентификаторами выделяем их
                    if change.record_type == "TXT" and ("id:" in value.lower() or "uuid" in value.lower() or "v=spf" in value.lower()):
                        lines.append(f"  ➤ {value}")
                        # Если есть идентификатор, выделяем его
                        if "id:" in value.lower():
                            id_part = value.split("id:")[1].strip().split()[0].strip('"\'')
                            lines.append(f"  🔑 ID: {id_part}")
                    else:
                        lines.append(f"  • {value}")
            else:
                lines.append("  Стало: —")
            
            lines.append("")  # Пустая строка между изменениями

    # Добавляем справочную информацию
    lines.append("💡 Используйте команду `/status` для просмотра полной информации.")

    return "\n".join(lines) 