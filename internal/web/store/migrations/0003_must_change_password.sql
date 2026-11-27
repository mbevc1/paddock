-- Set when an admin chose or reset the user's password; the user must pick their own before
-- reaching anything but the security page.
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1));
