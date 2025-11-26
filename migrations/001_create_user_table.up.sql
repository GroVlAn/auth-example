CREATE TABLE role
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    name varchar(255) NOT NULL UNIQUE,
    description text,
    is_default boolean NOT NULL DEFAULT FALSE,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permission
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    name varchar(255) NOT NULL UNIQUE,
    description text,
    is_default boolean NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_permission
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    role_id varchar(255) REFERENCES role(id) ON DELETE CASCADE NOT NULL,
    permission_id varchar(255) REFERENCES permission(id) ON DELETE CASCADE NOT NULL
);

CREATE TABLE auth_user
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    email text NOT NULL UNIQUE,
    username varchar(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    fullname text NOT NULL,
    is_active boolean NOT NULL DEFAULT TRUE,
    is_superuser boolean NOT NULL DEFAULT FALSE,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role_id varchar(255) REFERENCES role(id) ON DELETE SET NULL
);

CREATE TABLE access_token
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    token text NOT NULL UNIQUE,
    start_ttl timestamp NOT NULL,
    end_ttl timestamp NOT NULL,
    user_id varchar(255) NOT NULL
);

CREATE TABLE refresh_token
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    token text NOT NULL UNIQUE,
    start_ttl timestamp NOT NULL,
    end_ttl timestamp NOT NULL,
    user_id varchar(255) NOT NULL
);

CREATE TABLE access_refresh_token 
(
    id varchar(255) PRIMARY KEY NOT NULL UNIQUE,
    access_token_id varchar(255) REFERENCES access_token(id) ON DELETE CASCADE NOT NULL,
    refresh_token_id varchar(255) REFERENCES refresh_token(id) ON DELETE CASCADE NOT NULL
);