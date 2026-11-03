import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { after, before, beforeEach, test } from 'node:test';
import pg from 'pg';

import { createApp } from '../src/app.js';

const url = process.env.TEST_DATABASE_URL ?? 'postgres://nefarec@127.0.0.1:5434/nefarec_test';
if (!new URL(url).pathname.includes('test')) throw new Error('Refusing to run against a non-test database.');

const pool = new pg.Pool({ connectionString: url });
let base = '';
let close: () => void;

before(async () => {
  await pool.query(await readFile(new URL('../schema.sql', import.meta.url), 'utf8'));
  const app = createApp(pool, { jwtSecret: 'test-secret-that-is-long-enough-for-hs256!!', maxBackupMb: 1, keepBackups: 3 });
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => server.close();
});

beforeEach(async () => {
  await pool.query('TRUNCATE users CASCADE');
});

after(async () => {
  close();
  await pool.end();
});

async function call(method: string, path: string, body?: unknown, token?: string) {
  const res = await fetch(base + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const signup = (email = 'mo@example.test') =>
  call('POST', '/auth/signup', { email, password: 'correct horse', displayName: 'Mo' });

test('sign up returns tokens and a default profile', async () => {
  const r = await signup();
  assert.equal(r.status, 201);
  assert.ok(r.body.accessToken && r.body.refreshToken);
  assert.equal(r.body.user.email, 'mo@example.test');
  assert.equal(r.body.profile.displayName, 'Mo');
  assert.equal(r.body.profile.weeklyTarget, 3);
});

test('emails are unique regardless of case', async () => {
  await signup('Mo@Example.test');
  const r = await signup('mo@example.test');
  assert.equal(r.status, 409);
});

test('passwords are stored hashed and checked', async () => {
  await signup();
  const row = await pool.query('SELECT password_hash FROM users');
  assert.match(row.rows[0].password_hash, /^scrypt\$/);
  assert.equal((await call('POST', '/auth/login', { email: 'mo@example.test', password: 'nope' })).status, 401);
  assert.equal((await call('POST', '/auth/login', { email: 'MO@example.test', password: 'correct horse' })).status, 200);
});

test('short passwords and bad emails are rejected with a message', async () => {
  const r = await call('POST', '/auth/signup', { email: 'x@example.test', password: 'short', displayName: 'X' });
  assert.equal(r.status, 400);
  assert.match(r.body.message, /8 characters/);
  assert.equal((await call('POST', '/auth/signup', { email: 'nope', password: 'longenough', displayName: 'X' })).status, 400);
});

test('profile needs a token and updates partially', async () => {
  const { body } = await signup();
  assert.equal((await call('GET', '/me')).status, 401);
  const r = await call('PATCH', '/me/profile', { goal: 'strength', bodyweightKg: 82.5, weeklyTarget: 4 }, body.accessToken);
  assert.equal(r.status, 200);
  assert.equal(r.body.profile.goal, 'strength');
  assert.equal(r.body.profile.bodyweightKg, 82.5);
  assert.equal(r.body.profile.displayName, 'Mo');
  assert.equal((await call('PATCH', '/me/profile', { goal: 'flying' }, body.accessToken)).status, 400);
});

test('refresh tokens rotate and cannot be reused', async () => {
  const { body } = await signup();
  const first = await call('POST', '/auth/refresh', { refreshToken: body.refreshToken });
  assert.equal(first.status, 200);
  assert.notEqual(first.body.refreshToken, body.refreshToken);
  assert.equal((await call('POST', '/auth/refresh', { refreshToken: body.refreshToken })).status, 401);
  await call('POST', '/auth/logout', { refreshToken: first.body.refreshToken });
  assert.equal((await call('POST', '/auth/refresh', { refreshToken: first.body.refreshToken })).status, 401);
});

const backup = (n: number) => ({
  device: 'iPhone',
  appVersion: '1.0.0',
  schemaVersion: 2,
  summary: { routines: 1, sessions: n, sets: n * 3 },
  payload: { routines: [{ id: 1, name: 'Push' }], n },
});

test('backups are private, listed newest first and pruned', async () => {
  const a = (await signup('a@example.test')).body.accessToken;
  const b = (await signup('b@example.test')).body.accessToken;
  for (let i = 1; i <= 4; i++) assert.equal((await call('POST', '/backups', backup(i), a)).status, 201);

  const list = await call('GET', '/backups', undefined, a);
  assert.equal(list.body.backups.length, 3);
  assert.equal(list.body.backups[0].summary.sessions, 4);
  assert.equal(list.body.backups[0].payload, undefined);

  const latest = await call('GET', '/backups/latest', undefined, a);
  assert.equal(latest.body.payload.n, 4);

  const id = list.body.backups[0].id;
  assert.equal((await call('GET', `/backups/${id}`, undefined, b)).status, 404);
  assert.equal((await call('GET', '/backups', undefined, b)).body.backups.length, 0);
  assert.equal((await call('GET', '/backups/latest', undefined, b)).status, 404);
});

test('oversized backups are refused', async () => {
  const t = (await signup()).body.accessToken;
  const big = { ...backup(1), payload: { blob: 'x'.repeat(1.2 * 1024 * 1024) } };
  assert.equal((await call('POST', '/backups', big, t)).status, 413);
});

test('deleting the account removes everything', async () => {
  const t = (await signup()).body.accessToken;
  await call('POST', '/backups', backup(1), t);
  assert.equal((await call('DELETE', '/me', undefined, t)).status, 204);
  const left = await pool.query('SELECT (SELECT count(*) FROM backups) b, (SELECT count(*) FROM profiles) p');
  assert.equal(Number(left.rows[0].b), 0);
  assert.equal(Number(left.rows[0].p), 0);
  assert.equal((await call('GET', '/me', undefined, t)).status, 401);
});
