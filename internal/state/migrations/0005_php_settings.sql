-- Per-vhost PHP limits. The defaults are PHP's own, so existing vhosts keep their behaviour.
ALTER TABLE vhosts ADD COLUMN php_memory_mb INTEGER NOT NULL DEFAULT 128 CHECK (php_memory_mb > 0);
ALTER TABLE vhosts ADD COLUMN php_upload_mb INTEGER NOT NULL DEFAULT 2 CHECK (php_upload_mb > 0);
ALTER TABLE vhosts ADD COLUMN php_exec_s INTEGER NOT NULL DEFAULT 30 CHECK (php_exec_s > 0);
