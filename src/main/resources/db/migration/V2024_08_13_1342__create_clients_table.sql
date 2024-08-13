create table if not exists "clients"
(
    id                            uuid primary key default gen_random_uuid(),
    client_id                     text   not null,
    client_id_issued_at           timestamptz,
    client_secret                 text,
    client_secret_expires_at      timestamptz,
    client_name                   text   not null,
    client_authentication_methods text[] not null,
    authorization_grant_types     text[] not null,
    redirect_uris                 text[] not null,
    post_logout_redirect_uris     text[] not null,
    scopes                        text[] not null,
    client_settings               text   not null,
    token_settings                text   not null
);

create unique index on clients (client_id);
create unique index on clients (client_name);