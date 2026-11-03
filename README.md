# neFaRec API

Accounts, profiles and cloud backups for neFaRec. Runs on this Mac with its own
PostgreSQL cluster. Nothing is sent to a cloud provider, and nothing costs money.

The phone stays the source of truth while you train: workouts are recorded
locally and work offline. The API adds an account, a profile that follows you,
and full backups you can restore on a new or reset phone.

## Start

```bash
npm install
npm run db:initialize   # once: creates .local/postgres
npm run db:start        # PostgreSQL on 127.0.0.1:5434
npm run db:create       # once: creates the nefarec and nefarec_test databases
cp .env.example .env    # then set JWT_SECRET (openssl rand -base64 48)
npm run dev             # http://localhost:4100, /health to check
```

The iOS simulator reaches the API at `http://127.0.0.1:4100` (the app's
default). An Android emulator uses `http://10.0.2.2:4100`; a phone on your
Wi-Fi needs your Mac's address. Pass it with
`flutter run --dart-define=NEFAREC_API=http://<host>:4100`.

Stop the database with `npm run db:stop`.

## Endpoints

| Method | Path | |
|---|---|---|
| GET | `/health` | Liveness |
| POST | `/auth/signup` | `{email, password, displayName}` → tokens, user, profile |
| POST | `/auth/login` | `{email, password}` → tokens, user, profile |
| POST | `/auth/refresh` | `{refreshToken}` → new pair (old one is revoked) |
| POST | `/auth/logout` | `{refreshToken}` |
| GET | `/me` | User and profile |
| PATCH | `/me/profile` | Any of `displayName, goal, experience, unit, bodyweightKg, heightCm, weeklyTarget` |
| DELETE | `/me` | Deletes the account, profile and every backup |
| GET | `/backups` | List, newest first, without payloads |
| POST | `/backups` | `{schemaVersion, summary, payload, device?, appVersion?}`; keeps the latest 10 |
| GET | `/backups/latest`, `/backups/:id` | One backup with its payload |
| DELETE | `/backups/:id` | |

Access tokens are 15-minute HS256 JWTs; refresh tokens are random, stored only
as SHA-256 hashes, rotate on every use and last 30 days. Passwords are hashed
with scrypt. Sign-in and sign-up are rate limited per address and email.

## Tests

`npm test` runs the integration suite against `nefarec_test` (override with
`TEST_DATABASE_URL`; it refuses database names without `test`). `npm run
typecheck` checks types.

## Hosting later

Any Node host with PostgreSQL works. Free options exist (for example a small
free-tier Postgres plus a free Node service), but this repository deploys
nothing by itself. Use a fresh `JWT_SECRET` and HTTPS in any hosted setup.

## Local test account (development only)

Created while testing the app on the simulator against this local server.
Never use it on a hosted server. Its email and password are in
`.local/test-account.md`, which is git-ignored.
