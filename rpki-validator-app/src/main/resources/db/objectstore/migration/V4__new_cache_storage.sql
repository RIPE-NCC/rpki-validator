BEGIN;

DROP TABLE IF EXISTS repo_objects;

CREATE TABLE repo_objects (
  aki             CHARACTER VARYING(40)   NOT NULL,
  hash            CHARACTER VARYING(64)   NOT NULL,
  url             CHARACTER VARYING(2000) NOT NULL,
  object_type     CHARACTER (3)           NOT NULL,
  encoded         BYTEA                   NOT NULL,
  download_time   TIMESTAMP               NOT NULL DEFAULT NOW(),
  validation_time TIMESTAMP,
  PRIMARY KEY (url, hash),
  CHECK (object_type IN ('crl', 'mft', 'roa', 'cer'))
);

CREATE INDEX idx_repo_obj_url ON repo_objects (url);
CREATE INDEX idx_repo_obj_hash ON repo_objects (hash);
CREATE INDEX idx_repo_obj_aki_type ON repo_objects (aki, object_type);

COMMIT;