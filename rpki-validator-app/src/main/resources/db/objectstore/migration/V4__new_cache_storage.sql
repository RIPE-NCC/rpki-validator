BEGIN;

DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS crls;
DROP TABLE IF EXISTS manifests;
DROP TABLE IF EXISTS roas;

CREATE TABLE certificates (
  ski     CHARACTER VARYING(40)   NOT NULL,
  aki     CHARACTER VARYING(40)   NOT NULL,
  hash    CHARACTER VARYING(64)   NOT NULL,
  url     CHARACTER VARYING(2000) NOT NULL,
  encoded BYTEA                   NOT NULL
);

CREATE TABLE crls (
  aki     CHARACTER VARYING(40)   NOT NULL,
  hash    CHARACTER VARYING(64)   NOT NULL,
  url     CHARACTER VARYING(2000) NOT NULL,
  encoded BYTEA                   NOT NULL
);

CREATE TABLE manifests (
  aki     CHARACTER VARYING(40)   NOT NULL,
  hash    CHARACTER VARYING(64)   NOT NULL,
  url     CHARACTER VARYING(2000) NOT NULL,
  encoded BYTEA                   NOT NULL
);

CREATE TABLE roas (
  aki     CHARACTER VARYING(40)   NOT NULL,
  hash    CHARACTER VARYING(64)   NOT NULL,
  url     CHARACTER VARYING(2000) NOT NULL,
  encoded BYTEA                   NOT NULL
);

CREATE INDEX idx_certificates_aki ON certificates (aki);
CREATE INDEX idx_certificates_ski ON certificates (ski);
CREATE INDEX idx_crls_aki ON crls (aki);
CREATE INDEX idx_manifests_aki ON manifests (aki);
CREATE INDEX idx_roas_aki ON roas (aki);

COMMIT;
