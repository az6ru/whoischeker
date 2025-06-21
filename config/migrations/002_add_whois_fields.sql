-- Добавление новых полей в таблицу whois_records
ALTER TABLE whois_records ADD COLUMN registrar_url TEXT;
ALTER TABLE whois_records ADD COLUMN emails TEXT;
ALTER TABLE whois_records ADD COLUMN owner TEXT;
ALTER TABLE whois_records ADD COLUMN admin_contact TEXT;
ALTER TABLE whois_records ADD COLUMN tech_contact TEXT;
ALTER TABLE whois_records ADD COLUMN address TEXT;
ALTER TABLE whois_records ADD COLUMN phone TEXT;
ALTER TABLE whois_records ADD COLUMN dnssec TEXT;
ALTER TABLE whois_records ADD COLUMN whois_server TEXT;

-- Обновление длины поля status
ALTER TABLE whois_records ALTER COLUMN status TYPE TEXT; 