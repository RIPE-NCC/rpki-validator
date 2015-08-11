CREATE PROCEDURE DROP_TABLE_IF_EXISTS(IN TABLE_NAME VARCHAR(64))
PARAMETER STYLE JAVA MODIFIES SQL DATA LANGUAGE JAVA EXTERNAL NAME
  'net.ripe.rpki.validator.StoredProcedures.dropTableIfExists';

CALL DROP_TABLE_IF_EXISTS('REPO_OBJECTS');

CREATE TABLE REPO_OBJECTS (
  aki             VARCHAR(40)   NOT NULL,
  hash            VARCHAR(64)   NOT NULL,
  url             VARCHAR(2000) NOT NULL,
  object_type     CHAR (3)      NOT NULL,
  encoded         BLOB          NOT NULL,
  download_time   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  validation_time TIMESTAMP,
  PRIMARY KEY (hash, url),
  CHECK (object_type IN ('crl', 'mft', 'roa', 'cer', 'gbr'))
);

CREATE INDEX idx_repo_obj_url ON REPO_OBJECTS (url);
CREATE INDEX idx_repo_obj_hash ON REPO_OBJECTS (hash);
CREATE INDEX idx_repo_obj_aki_type ON REPO_OBJECTS (aki, object_type);

DROP PROCEDURE DROP_TABLE_IF_EXISTS;