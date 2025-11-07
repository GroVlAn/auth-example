CREATE TABLE user
(
    id VARCHAR(255) PRIMARY KEY NOT NULL UNIQUE,
    email text NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE access_token
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    token text NOT NULL UNIQUE,
    start_ttl TIMESTAMP NOT NULL,
    end_ttl TIMESTAMP NOT NULL,
    user_id VARCHAR(255) NOT NULL,
);

CREATE TABLE refresh_token
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    token text NOT NULL UNIQUE,
    start_ttl TIMESTAMP NOT NULL,
    end_ttl TIMESTAMP NOT NULL,
    user_agent TEXT NOT NULL,
    user_id VARCHAR(255) NOT NULL,
);