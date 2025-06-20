"""CLI интерфейс для администрирования бота."""

import asyncio
import argparse
import logging
from datetime import datetime
from typing import List, Dict
from collections import defaultdict

from sqlalchemy import select, func
from tabulate import tabulate

from src.db.service import DatabaseService
from src.db.models import Domain, WhoisRecord, DNSRecord
from src.utils.config import load_config

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BotAdmin:
    """Класс для администрирования бота."""

    def __init__(self):
        """Инициализация администратора."""
        self.config = load_config()
        self.db = DatabaseService(self.config["database"]["url"])

    async def get_statistics(self) -> Dict:
        """
        Получение общей статистики.

        Returns:
            Dict: Словарь со статистикой
        """
        async with self.db.async_session() as session:
            # Общее количество доменов
            domains_count = await session.scalar(
                select(func.count(Domain.id))
            )

            # Количество уникальных пользователей
            users_count = await session.scalar(
                select(func.count(func.distinct(Domain.chat_id)))
            )

            # Количество проверок
            whois_checks = await session.scalar(
                select(func.count(WhoisRecord.id))
            )
            dns_checks = await session.scalar(
                select(func.count(DNSRecord.id))
            )

            return {
                "domains_count": domains_count,
                "users_count": users_count,
                "total_checks": whois_checks + dns_checks,
                "whois_checks": whois_checks,
                "dns_checks": dns_checks,
            }

    async def get_domains_by_user(self) -> List[Dict]:
        """
        Получение статистики по доменам каждого пользователя.

        Returns:
            List[Dict]: Список статистики по пользователям
        """
        async with self.db.async_session() as session:
            # Получаем все домены с количеством проверок
            domains = await session.execute(
                select(
                    Domain,
                    func.count(WhoisRecord.id).label("whois_checks"),
                    func.count(DNSRecord.id).label("dns_checks"),
                )
                .outerjoin(WhoisRecord)
                .outerjoin(DNSRecord)
                .group_by(Domain.id)
                .order_by(Domain.chat_id)
            )
            
            # Группируем по пользователям
            users = defaultdict(list)
            for domain, whois_checks, dns_checks in domains.all():
                users[domain.chat_id].append({
                    "domain": domain.name,
                    "interval": domain.check_interval // 3600,  # в часах
                    "created_at": domain.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "whois_checks": whois_checks,
                    "dns_checks": dns_checks,
                })

            return [
                {"chat_id": chat_id, "domains": domains}
                for chat_id, domains in users.items()
            ]

    async def show_statistics(self):
        """Вывод общей статистики."""
        stats = await self.get_statistics()
        
        print("\n=== Общая статистика ===")
        print(f"Всего доменов: {stats['domains_count']}")
        print(f"Всего пользователей: {stats['users_count']}")
        print(f"Всего проверок: {stats['total_checks']}")
        print(f"WHOIS проверок: {stats['whois_checks']}")
        print(f"DNS проверок: {stats['dns_checks']}")

    async def show_users(self):
        """Вывод статистики по пользователям."""
        users = await self.get_domains_by_user()
        
        print("\n=== Статистика по пользователям ===")
        for user in users:
            print(f"\nПользователь {user['chat_id']}:")
            
            # Формируем таблицу доменов пользователя
            domains_data = []
            for domain in user['domains']:
                domains_data.append([
                    domain['domain'],
                    f"{domain['interval']} ч.",
                    domain['created_at'],
                    domain['whois_checks'],
                    domain['dns_checks'],
                ])
            
            print(tabulate(
                domains_data,
                headers=['Домен', 'Интервал', 'Добавлен', 'WHOIS', 'DNS'],
                tablefmt='grid'
            ))

    async def init(self):
        """Инициализация базы данных."""
        await self.db.init_db()


async def main():
    """Точка входа."""
    parser = argparse.ArgumentParser(description='Администрирование WhoisChecker')
    parser.add_argument(
        'command',
        choices=['stats', 'users'],
        help='Команда для выполнения'
    )

    args = parser.parse_args()
    admin = BotAdmin()
    await admin.init()

    try:
        if args.command == 'stats':
            await admin.show_statistics()
        elif args.command == 'users':
            await admin.show_users()
    finally:
        await admin.db.close()


if __name__ == '__main__':
    asyncio.run(main()) 