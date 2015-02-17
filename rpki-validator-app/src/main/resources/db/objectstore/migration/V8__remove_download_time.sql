BEGIN;

ALTER TABLE certificates DROP COLUMN download_time;
ALTER TABLE repo_objects DROP COLUMN download_time;
ALTER TABLE broken_objects DROP COLUMN download_time;

COMMIT;
