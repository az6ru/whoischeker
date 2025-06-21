# WhoisCheker

Telegram-бот для мониторинга изменений в WHOIS и DNS-записях доменов. Бот отслеживает изменения и уведомляет пользователей о любых обнаруженных изменениях.

## Возможности

- 🔍 Мониторинг WHOIS-информации доменов
- 📡 Отслеживание изменений DNS-записей (A, AAAA, MX, NS, TXT, CNAME)
- ⏰ Настраиваемые интервалы проверки для каждого домена
- 📱 Удобное управление через Telegram-бота
- 🔔 Мгновенные уведомления об изменениях

## Требования

- Python 3.11 или выше
- Poetry для управления зависимостями

## Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/yourusername/whoischeker.git
cd whoischeker
```

2. Установите Poetry (если еще не установлен):
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

3. Установите зависимости:
```bash
poetry install
```

4. Создайте конфигурационный файл:
```bash
cp config/config.example.yml config/config.yml
```

5. Отредактируйте `config/config.yml` и добавьте ваш токен бота и другие настройки.

## Запуск

1. Активируйте виртуальное окружение:
```bash
poetry shell
```

2. Запустите бота:
```bash
python -m src.bot.main
```

## Использование

1. Найдите бота в Telegram: `@your_bot_username`
2. Отправьте команду `/start` для начала работы
3. Используйте следующие команды:
   - `/add` - Добавить домен для отслеживания
   - `/list` - Показать список отслеживаемых доменов
   - `/delete` - Удалить домен из отслеживания
   - `/status` - Показать статус проверки доменов
   - `/help` - Показать справку

## Деплой на Coolify

Проект готов для деплоя на платформу [Coolify](https://coolify.io/).

### Использование Docker

1. Создайте файл с переменными окружения:
```bash
cp env.example .env
```

2. Отредактируйте `.env`, добавив токен бота и другие необходимые параметры:
```
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_ADMINS=123456789
```

3. Запустите с использованием Docker Compose:
```bash
docker-compose up -d
```

### Деплой на Coolify

1. В интерфейсе Coolify создайте новое приложение и выберите тип "Docker Compose".

2. Подключите репозиторий или укажите путь к коду.

3. Настройте переменные окружения в секции Environment:
   - `TELEGRAM_BOT_TOKEN`: токен вашего Telegram-бота
   - `TELEGRAM_ADMINS`: список ID администраторов (через запятую)

4. В настройках постоянного хранения (Persistent Storage) добавьте:
   - `/app/data`: для хранения базы данных
   - `/app/logs`: для хранения логов

5. Нажмите "Deploy" для запуска приложения.

## Разработка

1. Установите зависимости для разработки:
```bash
poetry install --with dev
```

2. Запустите тесты:
```bash
pytest
```

3. Проверьте качество кода:
```bash
black .
isort .
flake8
mypy .
```

## Лицензия

MIT License. См. файл `LICENSE` для подробностей.

## Автор

Ваше имя - [your.email@example.com](mailto:your.email@example.com) 