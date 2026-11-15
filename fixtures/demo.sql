-- Recovery Proof demo fixture: a tiny plain-SQL backup for the CI docker test.
-- Restores into the ephemeral container and satisfies checks.example.yaml
-- (users >= 1, orders >= 1, recent orders exist, users table present).
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id),
    total_cents INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO users (email) VALUES ('demo@example.com') ON CONFLICT DO NOTHING;
INSERT INTO orders (user_id, total_cents)
SELECT id, 4999 FROM users WHERE email = 'demo@example.com'
ON CONFLICT DO NOTHING;
