"""Модуль для управления миграциями базы данных."""

import logging
from pathlib import Path
from typing import List

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
            logger.info("Ожидающих миграций нет")
            
    except Exception as e:
        logger.error(f"Ошибка при настройке базы данных: {e}")
        raise 