-- A disabled admin keeps their account and TOTP secret but runs no admin operations.
ALTER TABLE admins ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1));
