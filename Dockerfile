FROM python:3.11-slim

WORKDIR /app

# Установка poetry
RUN pip install poetry==1.7.1

# Копирование файлов проекта
COPY pyproject.toml poetry.lock ./
COPY README.md ./

# Настройка poetry для установки зависимостей в системный Python
RUN poetry config virtualenvs.create false

# Установка зависимостей
RUN poetry install --only main --no-interaction --no-ansi

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