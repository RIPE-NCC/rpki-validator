BEGIN;

DROP TABLE IF EXISTS latest_http_snapshot;

CREATE TABLE latest_http_snapshot (
  url        CHARACTER VARYING(2000) NOT NULL,
  session_id CHARACTER VARYING(36)   NOT NULL,
  serial     INTEGER                 NOT NULL,
  PRIMARY KEY (url)
);

COMMIT;
