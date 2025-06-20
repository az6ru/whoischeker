"""Модуль сервиса для работы с базой данных."""

import logging
import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, joinedload

from src.db.models import Base, Domain, DNSRecord, WhoisRecord
from src.core.whois_checker import WhoisInfo
from src.core.dns_checker import DNSInfo

logger = logging.getLogger(__name__)


class DatabaseService:
    """Сервис для работы с базой данных."""

    def __init__(self, database_url: str):
        """
        Инициализация сервиса.

        Args:
            database_url: URL подключения к базе данных
        """
        self.engine = create_async_engine(database_url)
        self.async_session = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def init_db(self):
        """Инициализация базы данных."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("База данных инициализирована")

    async def close(self):
        """Закрытие соединения с базой данных."""
        await self.engine.dispose()
        logger.info("Соединение с базой данных закрыто")

    async def create_domain(
        self,
        name: str,
        chat_id: int,
        check_interval: int,
    ) -> Domain:
        """
        Создание нового домена.

        Args:
            name: Имя домена
            chat_id: ID чата
            check_interval: Интервал проверки в секундах

        Returns:
            Domain: Созданный домен
        """
        async with self.async_session() as session:
            domain = Domain(
                name=name,
                chat_id=chat_id,
                check_interval=check_interval,
            )
            session.add(domain)
            await session.commit()
            await session.refresh(domain)
            logger.info(f"Создан новый домен: {name}")
            return domain

    async def get_domain_by_name(self, name: str) -> Optional[Domain]:
        """
        Получение домена по имени.

        Args:
            name: Имя домена

        Returns:
            Optional[Domain]: Найденный домен или None
        """
        async with self.async_session() as session:
            result = await session.execute(
                select(Domain).where(Domain.name == name)
            )
            return result.scalar_one_or_none()

    async def get_domains_by_chat(self, chat_id: int) -> List[Domain]:
        """
        Получение списка доменов пользователя.

        Args:
            chat_id: ID чата

        Returns:
            List[Domain]: Список доменов
        """
        async with self.async_session() as session:
            result = await session.execute(
                select(Domain).where(Domain.chat_id == chat_id)
            )
            return list(result.scalars().all())

    async def get_all_domains(self) -> List[Domain]:
        """
        Получение всех доменов.

        Returns:
            List[Domain]: Список всех доменов
        """
        async with self.async_session() as session:
            result = await session.execute(select(Domain))
            return list(result.scalars().all())

    async def delete_domain(self, domain_id: int):
        """
        Удаление домена.

        Args:
            domain_id: ID домена
        """
        async with self.async_session() as session:
            domain = await session.get(Domain, domain_id)
            if domain:
                await session.delete(domain)
                await session.commit()
                logger.info(f"Удален домен: {domain.name}")

    async def save_whois_record(self, domain_id: int, whois_info: WhoisInfo):
        """
        Сохранение WHOIS записи.

        Args:
            domain_id: ID домена
            whois_info: Информация WHOIS
        """
        async with self.async_session() as session:
            # Преобразуем WhoisInfo в WhoisRecord
            record = WhoisRecord(
                domain_id=domain_id,
                registrar=whois_info.registrar,
                creation_date=whois_info.creation_date,
                expiration_date=whois_info.expiration_date,
                updated_date=whois_info.last_updated,
                status=json.dumps(whois_info.status) if whois_info.status else None,
                name_servers=json.dumps(whois_info.name_servers) if whois_info.name_servers else None,
                created_at=datetime.now(),
            )
            session.add(record)
            await session.commit()
            logger.debug(f"Сохранена WHOIS запись для домена {domain_id}")

    async def save_dns_records(self, domain_id: int, dns_info: DNSInfo):
        """
        Сохранение DNS записей.

        Args:
            domain_id: ID домена
            dns_info: Информация DNS
        """
        async with self.async_session() as session:
            for record_type, record_data in dns_info.records.items():
                record = DNSRecord(
                    domain_id=domain_id,
                    record_type=record_type,
                    values=json.dumps(record_data.values),
                    ttl=record_data.ttl,
                    created_at=datetime.now(),
                )
                session.add(record)
            await session.commit()
            logger.debug(f"Сохранены DNS записи для домена {domain_id}")

    async def get_last_whois_record(self, domain_id: int) -> Optional[WhoisInfo]:
        """
        Получение последней WHOIS записи.

        Args:
            domain_id: ID домена

        Returns:
            Optional[WhoisInfo]: Последняя запись или None
        """
        async with self.async_session() as session:
            # Получаем домен для имени
            domain = await session.get(Domain, domain_id)
            if not domain:
                return None

            # Получаем последнюю запись с предзагрузкой связи с доменом
            result = await session.execute(
                select(WhoisRecord)
                .where(WhoisRecord.domain_id == domain_id)
                .order_by(WhoisRecord.created_at.desc())
                .limit(1)
            )
            record = result.scalar_one_or_none()
            
            if not record:
                return None

            # Преобразуем WhoisRecord в WhoisInfo
            return WhoisInfo(
                domain_name=domain.name,  # Используем имя из предзагруженного домена
                registrar=record.registrar,
                creation_date=record.creation_date,
                expiration_date=record.expiration_date,
                last_updated=record.updated_date,
                status=json.loads(record.status) if record.status else None,
                name_servers=json.loads(record.name_servers) if record.name_servers else None,
                created_at=record.created_at,  # Добавляем время создания записи
            )

    async def get_last_dns_records(self, domain_id: int) -> Optional[DNSInfo]:
        """
        Получение последних DNS записей.

        Args:
            domain_id: ID домена

        Returns:
            Optional[DNSInfo]: Последние записи или None
        """
        async with self.async_session() as session:
            # Получаем домен для имени
            domain = await session.get(Domain, domain_id)
            if not domain:
                return None

            # Получаем время последней записи
            result = await session.execute(
                select(DNSRecord.created_at)
                .where(DNSRecord.domain_id == domain_id)
                .order_by(DNSRecord.created_at.desc())
                .limit(1)
            )
            last_time = result.scalar_one_or_none()
            
            if not last_time:
                return None

            # Получаем все записи за последнее время
            result = await session.execute(
                select(DNSRecord)
                .where(
                    DNSRecord.domain_id == domain_id,
                    DNSRecord.created_at == last_time,
                )
            )
            records = list(result.scalars().all())

            if not records:
                return None

            # Преобразуем записи в DNSInfo
            dns_info = DNSInfo(domain.name)  # Используем имя из предзагруженного домена
            for record in records:
                dns_info.add_record(
                    record.record_type,
                    json.loads(record.values),
                    record.ttl or 0
                )
            return dns_info 