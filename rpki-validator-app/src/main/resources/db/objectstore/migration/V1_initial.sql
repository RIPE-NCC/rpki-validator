CREATE TABLE retrieved_objects (
    hash character varying(2000) NOT NULL UNIQUE,
    url character varying(2000) NOT NULL,
    encoded_object character varying(8000) NOT NULL
);