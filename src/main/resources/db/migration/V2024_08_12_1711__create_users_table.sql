create table if not exists "users"
(
    id                  uuid primary key default gen_random_uuid(),
    username            text    not null,
    password            text    not null,
    authorities         text[]  not null,
    account_expired     boolean not null,
    account_locked      boolean not null,
    credentials_expired boolean not null,
    enabled             boolean not null
);

create unique index on users (username);