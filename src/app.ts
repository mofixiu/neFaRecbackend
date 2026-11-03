import express, { type NextFunction, type Request, type Response } from 'express';
import type pg from 'pg';
import { z } from 'zod';

import {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_DAYS,
  RateLimiter,
  hashPassword,
  hashToken,
  newRefreshToken,
  secretKey,
  signAccessToken,
  verifyAccessToken,
  verifyPassword,
} from './auth.js';

export interface Config {
  jwtSecret: string;
  maxBackupMb: number;
  /** Backups kept per account; older ones are pruned. */
  keepBackups: number;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const goals = ['strength', 'muscle', 'general', 'endurance', 'mobility'] as const;
const levels = ['beginner', 'intermediate', 'advanced'] as const;

const email = z.string().trim().toLowerCase().email().max(254);
const password = z.string().min(8, 'Use at least 8 characters.').max(200);
const displayName = z.string().trim().min(1).max(60);

const signupBody = z.object({ email, password, displayName, device: z.string().max(80).optional() });
const loginBody = z.object({ email, password: z.string().min(1).max(200), device: z.string().max(80).optional() });
const refreshBody = z.object({ refreshToken: z.string().min(20).max(200) });
const profileBody = z
  .object({
    displayName,
    goal: z.enum(goals),
    experience: z.enum(levels),
    unit: z.enum(['kg', 'lb']),
    bodyweightKg: z.number().min(20).max(400).nullable(),
    heightCm: z.number().min(90).max(250).nullable(),
    weeklyTarget: z.number().int().min(1).max(14),
  })
  .partial();
const backupBody = z.object({
  device: z.string().max(80).optional(),
  appVersion: z.string().max(40).optional(),
  schemaVersion: z.number().int().min(1),
  summary: z.object({
    routines: z.number().int().min(0),
    sessions: z.number().int().min(0),
    sets: z.number().int().min(0),
  }),
  payload: z.record(z.string(), z.unknown()),
});

interface ProfileRow {
  display_name: string;
  goal: string;
  experience: string;
  unit: string;
  bodyweight_kg: number | null;
  height_cm: number | null;
  weekly_target: number;
  updated_at: Date;
}

const profileJson = (p: ProfileRow) => ({
  displayName: p.display_name,
  goal: p.goal,
  experience: p.experience,
  unit: p.unit,
  bodyweightKg: p.bodyweight_kg,
  heightCm: p.height_cm,
  weeklyTarget: p.weekly_target,
  updatedAt: p.updated_at.toISOString(),
});

type Authed = Request & { userId: string };

export function createApp(pool: pg.Pool, config: Config) {
  const key = secretKey(config.jwtSecret);
  const authLimiter = new RateLimiter(10, 60_000);
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: `${config.maxBackupMb}mb` }));

  const parse = <T>(schema: z.ZodType<T>, body: unknown): T => {
    const r = schema.safeParse(body);
    if (!r.success) {
      throw new HttpError(400, 'invalid', r.error.issues[0]?.message ?? 'Invalid request.');
    }
    return r.data;
  };

  const limit = (req: Request, who: string) => {
    if (!authLimiter.allow(`${req.ip}|${who}`)) {
      throw new HttpError(429, 'rate_limited', 'Too many attempts. Wait a minute and try again.');
    }
  };

  async function issueTokens(userId: string, device?: string) {
    const refreshToken = newRefreshToken();
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, device, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(days => $4))`,
      [userId, hashToken(refreshToken), device ?? null, REFRESH_TTL_DAYS],
    );
    return {
      accessToken: await signAccessToken(userId, key),
      refreshToken,
      expiresIn: ACCESS_TTL_SECONDS,
    };
  }

  async function account(userId: string) {
    const r = await pool.query(
      `SELECT u.id, u.email, u.created_at, p.*
         FROM users u JOIN profiles p ON p.user_id = u.id WHERE u.id = $1`,
      [userId],
    );
    const row = r.rows[0];
    if (!row) throw new HttpError(401, 'unauthorized', 'This account no longer exists.');
    return {
      user: { id: row.id, email: row.email, createdAt: row.created_at.toISOString() },
      profile: profileJson(row),
    };
  }

  const requireAuth = async (req: Request, _res: Response, next: NextFunction) => {
    const header = req.get('authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const userId = token ? await verifyAccessToken(token, key) : null;
    if (!userId) return next(new HttpError(401, 'unauthorized', 'Sign in again.'));
    (req as Authed).userId = userId;
    next();
  };

  app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'nefarec-api' });
  });

  app.post('/auth/signup', async (req, res) => {
    const body = parse(signupBody, req.body);
    limit(req, body.email);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const exists = await client.query('SELECT 1 FROM users WHERE lower(email) = $1', [body.email]);
      if (exists.rowCount) {
        throw new HttpError(409, 'email_taken', 'An account with that email already exists. Sign in instead.');
      }
      const u = await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id', [
        body.email,
        await hashPassword(body.password),
      ]);
      const id = u.rows[0].id as string;
      await client.query('INSERT INTO profiles (user_id, display_name) VALUES ($1, $2)', [id, body.displayName]);
      await client.query('COMMIT');
      res.status(201).json({ ...(await issueTokens(id, body.device)), ...(await account(id)) });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  });

  app.post('/auth/login', async (req, res) => {
    const body = parse(loginBody, req.body);
    limit(req, body.email);
    const r = await pool.query('SELECT id, password_hash FROM users WHERE lower(email) = $1', [body.email]);
    const row = r.rows[0];
    // Same message either way, so the endpoint doesn't reveal who has an account.
    if (!row || !(await verifyPassword(body.password, row.password_hash))) {
      throw new HttpError(401, 'bad_credentials', 'That email and password don’t match.');
    }
    res.json({ ...(await issueTokens(row.id, body.device)), ...(await account(row.id)) });
  });

  app.post('/auth/refresh', async (req, res) => {
    const { refreshToken } = parse(refreshBody, req.body);
    const r = await pool.query(
      `UPDATE refresh_tokens SET revoked_at = now()
        WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
        RETURNING user_id, device`,
      [hashToken(refreshToken)],
    );
    const row = r.rows[0];
    if (!row) throw new HttpError(401, 'unauthorized', 'Your session ended. Sign in again.');
    res.json(await issueTokens(row.user_id, row.device ?? undefined));
  });

  app.post('/auth/logout', async (req, res) => {
    const { refreshToken } = parse(refreshBody, req.body);
    await pool.query('UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1', [hashToken(refreshToken)]);
    res.status(204).end();
  });

  app.get('/me', requireAuth, async (req, res) => {
    res.json(await account((req as Authed).userId));
  });

  app.patch('/me/profile', requireAuth, async (req, res) => {
    const body = parse(profileBody, req.body);
    const columns: Record<string, string> = {
      displayName: 'display_name',
      goal: 'goal',
      experience: 'experience',
      unit: 'unit',
      bodyweightKg: 'bodyweight_kg',
      heightCm: 'height_cm',
      weeklyTarget: 'weekly_target',
    };
    const sets: string[] = [];
    const values: unknown[] = [];
    for (const [k, v] of Object.entries(body)) {
      values.push(v);
      sets.push(`${columns[k]} = $${values.length}`);
    }
    if (sets.length) {
      values.push((req as Authed).userId);
      await pool.query(
        `UPDATE profiles SET ${sets.join(', ')}, updated_at = now() WHERE user_id = $${values.length}`,
        values,
      );
    }
    res.json(await account((req as Authed).userId));
  });

  /** Deletes the account, profile and every backup. */
  app.delete('/me', requireAuth, async (req, res) => {
    await pool.query('DELETE FROM users WHERE id = $1', [(req as Authed).userId]);
    res.status(204).end();
  });

  app.get('/backups', requireAuth, async (req, res) => {
    const r = await pool.query(
      `SELECT id, created_at, device, app_version, schema_version, size_bytes, summary
         FROM backups WHERE user_id = $1 ORDER BY created_at DESC`,
      [(req as Authed).userId],
    );
    res.json({
      backups: r.rows.map((b) => ({
        id: b.id,
        createdAt: b.created_at.toISOString(),
        device: b.device,
        appVersion: b.app_version,
        schemaVersion: b.schema_version,
        sizeBytes: b.size_bytes,
        summary: b.summary,
      })),
    });
  });

  app.post('/backups', requireAuth, async (req, res) => {
    const body = parse(backupBody, req.body);
    const userId = (req as Authed).userId;
    const json = JSON.stringify(body.payload);
    const r = await pool.query(
      `INSERT INTO backups (user_id, device, app_version, schema_version, size_bytes, summary, payload)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at`,
      [userId, body.device ?? null, body.appVersion ?? null, body.schemaVersion, Buffer.byteLength(json), body.summary, json],
    );
    await pool.query(
      `DELETE FROM backups WHERE user_id = $1 AND id NOT IN (
         SELECT id FROM backups WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2)`,
      [userId, config.keepBackups],
    );
    res.status(201).json({ id: r.rows[0].id, createdAt: r.rows[0].created_at.toISOString() });
  });

  app.get('/backups/:id', requireAuth, async (req, res) => {
    const id = String(req.params.id);
    const userId = (req as Authed).userId;
    const select = 'SELECT id, created_at, schema_version, payload FROM backups WHERE user_id = $1';
    let rows: Array<Record<string, any>> = [];
    if (id === 'latest') {
      rows = (await pool.query(`${select} ORDER BY created_at DESC LIMIT 1`, [userId])).rows;
    } else if (z.string().uuid().safeParse(id).success) {
      rows = (await pool.query(`${select} AND id = $2`, [userId, id])).rows;
    }
    const b = rows[0];
    if (!b) throw new HttpError(404, 'not_found', 'No backup found.');
    res.json({ id: b.id, createdAt: b.created_at.toISOString(), schemaVersion: b.schema_version, payload: b.payload });
  });

  app.delete('/backups/:id', requireAuth, async (req, res) => {
    const id = String(req.params.id);
    if (!z.string().uuid().safeParse(id).success) throw new HttpError(404, 'not_found', 'No backup found.');
    await pool.query('DELETE FROM backups WHERE user_id = $1 AND id = $2', [(req as Authed).userId, id]);
    res.status(204).end();
  });

  app.use((_req, _res, next) => next(new HttpError(404, 'not_found', 'Not found.')));

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.code, message: err.message });
      return;
    }
    const e = err as { type?: string };
    if (e?.type === 'entity.too.large') {
      res.status(413).json({ error: 'too_large', message: `Backups are limited to ${config.maxBackupMb} MB.` });
      return;
    }
    if (e?.type === 'entity.parse.failed') {
      res.status(400).json({ error: 'invalid', message: 'The request body is not valid JSON.' });
      return;
    }
    console.error(err);
    res.status(500).json({ error: 'server', message: 'Something went wrong on the server.' });
  });

  return app;
}
