"""Модуль для управления миграциями базы данных."""

import logging
import os
import re
from pathlib import Path
from typing import List, Tuple

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from src.utils.config import load_config

logger = logging.getLogger(__name__)


class DatabaseMigrator:
    """Класс для управления миграциями базы данных."""

    def __init__(self, database_url: str):
        """
        Инициализация мигратора.

        Args:
            database_url: URL подключения к базе данных
        """
        self.database_url = database_url
        self.engine = create_engine(database_url)
        
        # Путь к директории с миграциями
        self.migrations_dir = Path(__file__).parent / "migrations"
        self.migrations_dir.mkdir(exist_ok=True)
        
        # Путь к директории с SQL миграциями
        self.sql_migrations_dir = Path("config/migrations")
        
        # Путь к файлу конфигурации alembic
        self.alembic_cfg = Config()
        self.alembic_cfg.set_main_option("script_location", str(self.migrations_dir))
        self.alembic_cfg.set_main_option("sqlalchemy.url", database_url)

    async def init_migrations(self):
        """Инициализация системы миграций."""
        try:
            # Создаем директорию versions если её нет
            versions_dir = self.migrations_dir / "versions"
            versions_dir.mkdir(exist_ok=True)

            # Проверяем наличие таблицы alembic_version
            with self.engine.connect() as conn:
                result = conn.execute(text(
                    "SELECT EXISTS ("
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_name = 'alembic_version'"
                    ")"
                ))
                has_alembic_version = result.scalar()

            if not has_alembic_version:
                # Инициализируем alembic если таблицы нет
                command.init(self.alembic_cfg, str(self.migrations_dir))
                logger.info("Система миграций инициализирована")
            else:
                logger.info("Система миграций уже инициализирована")

        except Exception as e:
            logger.error(f"Ошибка при инициализации миграций: {e}")
            raise

    async def create_migration(self, message: str):
        """
        Создание новой миграции.

        Args:
            message: Сообщение, описывающее миграцию
        """
        try:
            # Создаем новую ревизию
            command.revision(
                self.alembic_cfg,
                message=message,
                autogenerate=True,
            )
            logger.info(f"Создана новая миграция: {message}")
        except Exception as e:
            logger.error(f"Ошибка при создании миграции: {e}")
            raise

    async def get_pending_migrations(self) -> List[str]:
        """
        Получение списка ожидающих применения миграций.

        Returns:
            List[str]: Список имен миграций
        """
        try:
            # Получаем текущую ревизию
            script = ScriptDirectory.from_config(self.alembic_cfg)
            with self.engine.connect() as conn:
                context = command.MigrationContext.configure(conn)
                current_rev = context.get_current_revision()

            # Получаем список ожидающих миграций
            pending = []
            for sc in script.walk_revisions():
                if sc.revision != current_rev:
                    pending.append(sc.revision)
                else:
                    break

            return pending
        except Exception as e:
            logger.error(f"Ошибка при получении списка миграций: {e}")
            raise

    async def apply_migrations(self):
        """Применение всех ожидающих миграций."""
        try:
            # Применяем миграции
            command.upgrade(self.alembic_cfg, "head")
            logger.info("Все миграции успешно применены")
        except Exception as e:
            logger.error(f"Ошибка при применении миграций: {e}")
            raise

    async def rollback_migration(self):
        """Откат последней миграции."""
        try:
            # Откатываем на одну миграцию назад
            command.downgrade(self.alembic_cfg, "-1")
            logger.info("Последняя миграция успешно откачена")
        except Exception as e:
            logger.error(f"Ошибка при откате миграции: {e}")
            raise
        
    async def check_sql_migrations(self) -> List[Tuple[int, str, Path]]:
        """
        Проверка наличия SQL миграций.
        
        Returns:
            List[Tuple[int, str, Path]]: Список кортежей (номер миграции, имя миграции, путь к файлу)
        """
        migrations = []
        
        if not self.sql_migrations_dir.exists():
            return migrations
        
        # Проверяем таблицу для хранения выполненных SQL миграций
        with self.engine.connect() as conn:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS sql_migrations ("
                "id INTEGER PRIMARY KEY, "
                "name TEXT NOT NULL, "
                "applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            ))
            conn.commit()
            
            # Получаем список выполненных миграций
            result = conn.execute(text("SELECT id FROM sql_migrations"))
            executed_migrations = {row[0] for row in result}
        
        # Получаем список файлов миграций
        pattern = re.compile(r"^(\d+)_(.+)\.sql$")
        
        for file in self.sql_migrations_dir.glob("*.sql"):
            match = pattern.match(file.name)
            if match:
                migration_id = int(match.group(1))
                migration_name = match.group(2)
                
                # Проверяем, выполнялась ли эта миграция ранее
                if migration_id not in executed_migrations:
                    migrations.append((migration_id, migration_name, file))
        
        # Сортируем миграции по номеру
        migrations.sort(key=lambda x: x[0])
        return migrations

    async def apply_sql_migrations(self):
        """Применение всех SQL миграций."""
        pending_migrations = await self.check_sql_migrations()
        
        if not pending_migrations:
            logger.info("Нет ожидающих SQL миграций")
            return
        
        logger.info(f"Найдено {len(pending_migrations)} SQL миграций для выполнения")
        
        for migration_id, migration_name, file_path in pending_migrations:
            try:
                # Читаем SQL из файла
                with open(file_path, "r", encoding="utf-8") as f:
                    sql = f.read()
                
                logger.info(f"Применение SQL миграции {migration_id}: {migration_name}")
                
                # Выполняем SQL
                with self.engine.connect() as conn:
                    # Разделяем SQL на отдельные команды
                    for stmt in sql.split(";"):
                        if stmt.strip():
                            conn.execute(text(stmt))
                    
                    # Отмечаем миграцию как выполненную
                    conn.execute(
                        text("INSERT INTO sql_migrations (id, name) VALUES (:id, :name)"),
                        {"id": migration_id, "name": migration_name}
                    )
                    conn.commit()
                
                logger.info(f"SQL миграция {migration_id}: {migration_name} успешно применена")
                
            except Exception as e:
                logger.error(f"Ошибка при применении SQL миграции {migration_id}: {e}")
                raise


async def setup_database():
    """Настройка базы данных и применение миграций."""
    config = load_config()
    migrator = DatabaseMigrator(config["database"]["url"])
    
    try:
        # Инициализируем систему миграций
        await migrator.init_migrations()
        
        # Проверяем наличие ожидающих миграций
        pending = await migrator.get_pending_migrations()
        if pending:
            logger.info(f"Найдено {len(pending)} ожидающих миграций")
            await migrator.apply_migrations()
        else:
            logger.info("Ожидающих Alembic миграций нет")
        
        # Применяем SQL миграции
        await migrator.apply_sql_migrations()
            
    except Exception as e:
        logger.error(f"Ошибка при настройке базы данных: {e}")
        raise 