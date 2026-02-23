-- ─── Auth service ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            TEXT        PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ─── User service ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_profiles (
    id         TEXT        PRIMARY KEY,
    email      TEXT        NOT NULL UNIQUE,
    name       TEXT        NOT NULL DEFAULT '',
    bio        TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── Joke service ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS jokes (
    id         TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL,
    content    TEXT        NOT NULL,
    category   TEXT        NOT NULL DEFAULT 'general',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_jokes_category   ON jokes(category);
CREATE INDEX IF NOT EXISTS idx_jokes_user_id    ON jokes(user_id);
CREATE INDEX IF NOT EXISTS idx_jokes_created_at ON jokes(created_at DESC);
