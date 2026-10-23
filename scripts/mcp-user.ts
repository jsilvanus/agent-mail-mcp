import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { hash } from '@node-rs/argon2';
import { SqliteUserStore } from '../src/storage/sqlite.js';

const dbPath = process.env.STORAGE_PATH ?? './data/app.sqlite';
mkdirSync(dirname(dbPath), { recursive: true });
const db = new DatabaseSync(dbPath);
db.exec('CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, created_at INTEGER NOT NULL);');
try { db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch { /* already exists */ }
const users = new SqliteUserStore(db);

const [command, ...args] = process.argv.slice(2);
const value = (flag: string) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
const hashPassword = (password: string) => hash(password, { algorithm: 2 });

switch (command) {
  case 'create': {
    const name = value('--name');
    const password = value('--password');
    if (!name || !password) throw new Error('create requires --name and --password');
    const id = value('--id') ?? randomUUID();
    users.createUser({ id, name, ...(value('--email') ? {email:value('--email')} : {}), passwordHash: await hashPassword(password), createdAt: Date.now() });
    const {passwordHash: _, ...safe} = users.getUser(id)!;
    console.log(JSON.stringify(safe, null, 2));
    break;
  }
  case 'list': {
    console.log(JSON.stringify(users.listUsers().map(({passwordHash:_, ...user}) => user), null, 2));
    break;
  }
  case 'get': {
    const id = args[0];
    if (!id) throw new Error('get requires <id>');
    const user = users.getUser(id);
    if (!user) { console.log('null'); break; }
    const {passwordHash:_, ...safe} = user;
    console.log(JSON.stringify(safe, null, 2));
    break;
  }
  case 'update': {
    const id = args[0];
    if (!id) throw new Error('update requires <id>');
    const password = value('--password');
    const user = users.updateUser(id, {
      ...(value('--name') ? {name:value('--name')} : {}),
      ...(value('--email') ? {email:value('--email')} : {}),
      ...(password ? {passwordHash:await hashPassword(password)} : {}),
    });
    if (!user) throw new Error('User not found: ' + id);
    const {passwordHash:_, ...safe} = user;
    console.log(JSON.stringify(safe, null, 2));
    break;
  }
  case 'delete': {
    const id = args[0];
    if (!id) throw new Error('delete requires <id>');
    if (!users.deleteUser(id)) throw new Error('User not found: ' + id);
    console.log('Deleted ' + id);
    break;
  }
  default:
    console.log('Usage: npm run user -- <create|list|get|update|delete> ...');
    console.log('  create --name "Name" --email "user@example.com" --password "secret"');
    console.log('  update <id> --name "New name" --email "new@example.com" --password "new-secret"');
    process.exitCode = 1;
}
