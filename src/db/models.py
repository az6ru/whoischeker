"""Модуль с моделями базы данных."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Базовый класс для всех моделей."""
    pass


class Domain(Base):
    """Модель домена."""

    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    chat_id: Mapped[int] = mapped_column(Integer)
    check_interval: Mapped[int] = mapped_column(Integer)  # в секундах
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now,
        onupdate=datetime.now,
    )

    # Связи
    whois_records: Mapped[List["WhoisRecord"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
    )
    dns_records: Mapped[List["DNSRecord"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
    )


class WhoisRecord(Base):
    """Модель WHOIS записи."""

    __tablename__ = "whois_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    registrar: Mapped[Optional[str]] = mapped_column(String(255))
    creation_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    expiration_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    updated_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    status: Mapped[Optional[str]] = mapped_column(String(255))
    name_servers: Mapped[Optional[List[str]]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now,
    )

    # Связи
    domain: Mapped[Domain] = relationship(back_populates="whois_records")


class DNSRecord(Base):
    """Модель DNS записи."""

    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    record_type: Mapped[str] = mapped_column(String(10))
    values: Mapped[List[str]] = mapped_column(Text)
    ttl: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now,
    )

    # Связи
    domain: Mapped[Domain] = relationship(back_populates="dns_records")


def init_db(database_url: str) -> None:
    """
    Инициализация базы данных.

    Args:
        database_url: URL подключения к базе данных
    """
    engine = create_engine(database_url)
    Base.metadata.create_all(engine) 