-- Who suspended a vhost: an owner may lift only their own suspension. Vhosts suspended
-- before this column existed were suspended by an admin.
ALTER TABLE vhosts ADD COLUMN suspended_by TEXT CHECK (suspended_by IN ('admin', 'owner'));
UPDATE vhosts SET suspended_by = 'admin' WHERE status = 'suspended';
