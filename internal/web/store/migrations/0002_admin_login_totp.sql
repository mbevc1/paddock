-- Whether an admin's login asks for a TOTP code. Admin operations need one from the agent
-- either way; root turns it off with `paddock admin login-totp-off`.
ALTER TABLE users ADD COLUMN admin_login_totp INTEGER NOT NULL DEFAULT 1
    CHECK (admin_login_totp IN (0, 1) AND (role = 'admin' OR admin_login_totp = 1));
