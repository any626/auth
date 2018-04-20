CREATE EXTENSION citext;

CREATE TABLE user (
    id bigserial PRIMARY KEY,
    email citext UNIQUE NOT NULL,
    password varchar NULL,
    disabled boolean DEFAULT false,
    created_at timestamptz DEFAULT NOW(),
    updated_at timestamptz DEFAULT NOW()
);