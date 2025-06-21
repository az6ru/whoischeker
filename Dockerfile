FROM python:3.11-slim

WORKDIR /app

# Установка московского времени (МСК, UTC+3)
RUN apt-get update && apt-get install -y tzdata
ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Установка только необходимых зависимостей без poetry
RUN pip install \
    aiogram==3.4.1 \
    sqlalchemy==2.0.28 \
    alembic==1.13.1 \
    pyyaml==6.0.1 \
    python-whois==0.8.0 \
    dnspython==2.6.1 \
    aiosqlite==0.20.0 \
    asyncio==3.4.3 \
    python-dotenv==1.0.1 \
    tabulate==0.9.0

# Копирование исходного кода
COPY src/ ./src/
COPY config/ ./config/

# Создание необходимых директорий
RUN mkdir -p data logs

# Переименование config.example.yml в config.yml
# Этот файл содержит базовые настройки, которые будут переопределены
# переменными окружения из .env файла или Docker Environment
RUN cp config/config.example.yml config/config.yml

# Установка разрешений
RUN chmod -R 777 data logs

# Добавление проверки работоспособности
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -m src.utils.healthcheck || exit 1

# Определение точки входа
CMD ["python", "-m", "src.bot.main"] 