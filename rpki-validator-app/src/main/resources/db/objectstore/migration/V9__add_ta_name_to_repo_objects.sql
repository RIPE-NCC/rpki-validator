BEGIN;

ALTER TABLE certificates   ADD COLUMN ta_name CHARACTER VARYING(80);
ALTER TABLE repo_objects   ADD COLUMN ta_name CHARACTER VARYING(80);
ALTER TABLE broken_objects ADD COLUMN ta_name CHARACTER VARYING(80);


DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS repo_objects;

CREATE TABLE certificates (
  ski             CHARACTER VARYING(40)   NOT NULL,
  aki             CHARACTER VARYING(40)   NOT NULL,
  hash            CHARACTER VARYING(64)   NOT NULL,
  url             CHARACTER VARYING(2000) NOT NULL,
  encoded         BYTEA                   NOT NULL,
  validation_time TIMESTAMP,
  ta_name         CHARACTER VARYING(80),
  PRIMARY KEY (url, hash, ta_name)
);

-- All the other objects
CREATE TABLE repo_objects (
  aki             CHARACTER VARYING(40)   NOT NULL,
  hash            CHARACTER VARYING(64)   NOT NULL,
  url             CHARACTER VARYING(2000) NOT NULL,
  object_type     CHARACTER VARYING(10)   NOT NULL,
  encoded         BYTEA                   NOT NULL,
  validation_time TIMESTAMP,
  ta_name         CHARACTER VARYING(80),
  PRIMARY KEY (url, hash, ta_name),
  CHECK (object_type IN ('crl', 'manifest', 'roa'))
);

CREATE INDEX idx_certificates_aki ON certificates (aki);
CREATE INDEX idx_certificates_ski ON certificates (ski);
CREATE INDEX idx_repo_obj_aki ON repo_objects (aki);
CREATE INDEX idx_repo_obj_aki_type ON repo_objects (aki, object_type);

COMMIT;