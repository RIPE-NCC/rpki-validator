DROP TABLE retrieved_objects;

CREATE TABLE retrieved_objects (
    hash CHARACTER VARYING(2000) NOT NULL PRIMARY KEY,
    uri CHARACTER VARYING(2000) NOT NULL,
    encoded_object CHARACTER VARYING NOT NULL,
    expires TIMESTAMP NOT NULL,
    time_seen DATETIME NOT NULL
);

CREATE INDEX uri_idx ON retrieved_objects(uri);