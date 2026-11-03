-- neFaRec API schema. Applied on every start; every statement is idempotent.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON users (lower(email));

CREATE TABLE IF NOT EXISTS profiles (
  user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  display_name text NOT NULL,
  goal text NOT NULL DEFAULT 'general',
  experience text NOT NULL DEFAULT 'beginner',
  unit text NOT NULL DEFAULT 'kg',
  bodyweight_kg real,
  height_cm real,
  weekly_target smallint NOT NULL DEFAULT 3,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Opaque refresh tokens, stored only as SHA-256 hashes. Rotated on every use.
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  device text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user ON refresh_tokens (user_id);

-- Full snapshots of the phone's local database. The phone stays the source of
-- truth while you train; these let you restore on a new or reset phone.
CREATE TABLE IF NOT EXISTS backups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  device text,
  app_version text,
  schema_version integer NOT NULL,
  size_bytes integer NOT NULL,
  summary jsonb NOT NULL,
  payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS backups_user_created ON backups (user_id, created_at DESC);
