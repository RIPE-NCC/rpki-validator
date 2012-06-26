CREATE TABLE retrieved_objects (
    hash character varying(200) NOT NULL UNIQUE,
    url character varying(2000) NOT NULL,
    encoded_object character varying(2000) NOT NULL
);