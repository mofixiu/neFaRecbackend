import { readFile } from 'node:fs/promises';
import pg from 'pg';

import { createApp } from './app.js';

const port = Number(process.env.PORT ?? 4100);
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://nefarec@127.0.0.1:5434/nefarec';
const jwtSecret = process.env.JWT_SECRET ?? '';

if (jwtSecret.length < 32 || jwtSecret.startsWith('change-me')) {
  console.error('Set JWT_SECRET in .env to a long random string (openssl rand -base64 48).');
  process.exit(1);
}

export async function applySchema(pool: pg.Pool) {
  const sql = await readFile(new URL('../schema.sql', import.meta.url), 'utf8');
  await pool.query(sql);
}

const pool = new pg.Pool({ connectionString: databaseUrl });
await applySchema(pool);

const app = createApp(pool, {
  jwtSecret,
  maxBackupMb: Number(process.env.MAX_BACKUP_MB ?? 8),
  keepBackups: 10,
});

app.listen(port, () => {
  console.log(`neFaRec API on http://localhost:${port}`);
});
