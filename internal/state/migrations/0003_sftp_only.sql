-- Access accounts are SFTP only. Shell accounts are refused before this runs (preconditions in
-- store.go), since their Linux users and jails need the previous release to remove.
ALTER TABLE access_accounts DROP COLUMN kind;
ALTER TABLE limits DROP COLUMN shell_allowed;
