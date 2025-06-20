-- Удаляем таблицу users
DROP TABLE IF EXISTS users;

-- Создаем временную таблицу
CREATE TABLE domains_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    chat_id INTEGER NOT NULL,
    check_interval INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Копируем данные
INSERT INTO domains_new (id, name, chat_id, check_interval, created_at, updated_at)
SELECT id, name, COALESCE(user_id, 0), check_interval, created_at, updated_at
FROM domains;

-- Удаляем старую таблицу
DROP TABLE domains;

-- Переименовываем новую таблицу
ALTER TABLE domains_new RENAME TO domains;

-- Обновляем таблицу domains
ALTER TABLE domains DROP COLUMN IF EXISTS user_id;
ALTER TABLE domains DROP COLUMN IF EXISTS is_active;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS chat_id INTEGER NOT NULL; 