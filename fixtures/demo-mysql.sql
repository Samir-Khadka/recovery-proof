-- Recovery Proof demo fixture for MySQL: a tiny mysqldump-style backup for
-- the CI docker test. Restores into the ephemeral container and satisfies
-- checks.mysql.example.yaml (users >= 1, orders >= 1, recent orders exist,
-- users table present). No CREATE DATABASE / USE: the checker restores into
-- the database named by --database (default recovery_proof).
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    total_cents INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
INSERT INTO users (email) VALUES ('demo@example.com')
  ON DUPLICATE KEY UPDATE email = email;
INSERT INTO orders (user_id, total_cents)
  SELECT id, 4999 FROM users WHERE email = 'demo@example.com';
