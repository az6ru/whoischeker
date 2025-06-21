"""Модуль планировщика задач для регулярных проверок доменов."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from src.core.changes import (
    DomainChanges,
    compare_dns_records,
    compare_whois_records,
    format_changes_message,
)
from src.core.dns_checker import DNSChecker
from src.core.whois_checker import WhoisChecker
from src.db.models import Domain, DNSRecord, WhoisRecord
from src.db.service import DatabaseService

logger = logging.getLogger(__name__)


class DomainCheckScheduler:
    """Планировщик проверок доменов."""

    def __init__(
        self,
        db_service: DatabaseService,
        whois_checker: WhoisChecker,
        dns_checker: DNSChecker,
        notify_callback: callable,
    ):
        """
        Инициализация планировщика.

        Args:
            db_service: Сервис для работы с БД
            whois_checker: Сервис проверки WHOIS
            dns_checker: Сервис проверки DNS
            notify_callback: Функция для отправки уведомлений
        """
        self.db = db_service
        self.whois_checker = whois_checker
        self.dns_checker = dns_checker
        self.notify_callback = notify_callback
        self._running_tasks: Dict[int, asyncio.Task] = {}
        self._stop_event = asyncio.Event()

    async def start(self):
        """Запуск планировщика."""
        logger.info("Запуск планировщика проверок доменов")
        self._stop_event.clear()
        
        # Загружаем все активные домены
        domains = await self.db.get_all_domains()
        
        # Запускаем задачи проверки для каждого домена
        for domain in domains:
            if domain.id not in self._running_tasks:
                task = asyncio.create_task(
                    self._domain_check_loop(domain),
                    name=f"check_{domain.name}",
                )
                self._running_tasks[domain.id] = task

    async def stop(self):
        """Остановка планировщика."""
        logger.info("Остановка планировщика проверок доменов")
        self._stop_event.set()
        
        # Ожидаем завершения всех задач
        if self._running_tasks:
            await asyncio.gather(*self._running_tasks.values())
        self._running_tasks.clear()

    async def add_domain(self, domain: Domain):
        """
        Добавление нового домена для проверки.

        Args:
            domain: Объект домена
        """
        if domain.id not in self._running_tasks:
            task = asyncio.create_task(
                self._domain_check_loop(domain),
                name=f"check_{domain.name}",
            )
            self._running_tasks[domain.id] = task
            logger.info(f"Добавлена задача проверки для домена {domain.name}")

    async def remove_domain(self, domain_id: int):
        """
        Удаление домена из проверки.

        Args:
            domain_id: ID домена
        """
        if domain_id in self._running_tasks:
            task = self._running_tasks.pop(domain_id)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            logger.info(f"Удалена задача проверки для домена {domain_id}")

    async def _domain_check_loop(self, domain: Domain):
        """
        Цикл проверки домена.

        Args:
            domain: Объект домена
        """
        # Флаг первой проверки
        first_check = True
        
        while not self._stop_event.is_set():
            try:
                logger.info(f"Запуск проверки для домена {domain.name}")
                
                # Получаем последние записи
                last_whois = await self.db.get_last_whois_record(domain.id)
                last_dns_records = await self.db.get_last_dns_records(domain.id)
                
                # Определяем, первая ли это проверка
                is_first_check = last_whois is None or not last_dns_records or first_check
                
                if is_first_check:
                    logger.info(f"Первая проверка домена {domain.name}")
                else:
                    logger.info(f"Повторная проверка домена {domain.name}")

                # Получаем новые данные
                new_whois = await self.whois_checker.get_whois_info(domain.name)
                new_dns_records = await self.dns_checker.get_dns_info(domain.name)

                # Сохраняем новые записи
                await self.db.save_whois_record(domain.id, new_whois)
                await self.db.save_dns_records(domain.id, new_dns_records)

                # Проверяем изменения только если это не первая проверка
                if not is_first_check:
                    whois_changes = compare_whois_records(last_whois, new_whois)
                    dns_changes = compare_dns_records(last_dns_records, new_dns_records)

                    # Если есть изменения, отправляем уведомление
                    if whois_changes or dns_changes:
                        changes = DomainChanges(
                            domain=domain,
                            whois_changes=whois_changes,
                            dns_changes=dns_changes,
                            check_time=datetime.now(),
                        )
                        message = format_changes_message(changes)
                        await self.notify_callback(domain.chat_id, message)
                        logger.info(f"Обнаружены изменения для домена {domain.name}")
                    else:
                        logger.info(f"Изменений для домена {domain.name} не обнаружено")
                else:
                    logger.info(f"Первая проверка домена {domain.name}, уведомления не отправляются")
                    first_check = False  # Сбрасываем флаг первой проверки

            except Exception as e:
                logger.error(f"Ошибка при проверке домена {domain.name}: {e}")

            # Ждем до следующей проверки
            try:
                logger.debug(f"Ожидание {domain.check_interval} секунд до следующей проверки домена {domain.name}")
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=domain.check_interval,
                )
            except asyncio.TimeoutError:
                continue  # Продолжаем проверки
            else:
                break  # Получен сигнал остановки 