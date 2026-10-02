const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');

const port = Number(process.env.PORT || 4204);
const publicRoot = path.resolve(__dirname, '../frontend');
const jwtSecret = process.env.JWT_SECRET || 'project-pulse-development-secret-change-me';
const demoEmail = (process.env.DEMO_EMAIL || 'member@project.com').toLowerCase();
const demoPassword = process.env.DEMO_PASSWORD || 'pulse2026';
const memberDisplayNames = {
  '23BQ1A4202': 'A.Sa Charan',
  '23BQ1A4231': 'CH.Aparna',
  '23BQ1A4251': 'G.Kamesh',
  '24BQ5A4202': 'K.chandra sekhar'
};

const pool = new Pool({
  host: "localhost",
  user: "postgres",
  password: "5477",
  database: "quantum",
  port: 5432
});

pool.connect()
  .then(() => console.log("PostgreSQL connected"))
  .catch(err => {
    console.error("PostgreSQL connection failed:", err.message);
    process.exit(1);
  });

const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
const verifyPassword = (password, storedHash) => {
  const [salt, expected] = storedHash.split(':');
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
};
const memberAccounts = [
  ['23BQ1A4202', 'A.Sa Charan', '23BQ1A4202'],
  ['23BQ1A4231', 'CH.Aparna', '23BQ1A4231'],
  ['23BQ1A4251', 'G.Kamesh', '23BQ1A4251'],
  ['24BQ5A4203', 'K.chandra sekhar', '24BQ5A4203']
];
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS quiz_attempts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      score INTEGER NOT NULL CHECK (score >= 0),
      total_questions INTEGER NOT NULL CHECK (total_questions > 0),
      duration_seconds INTEGER NOT NULL CHECK (duration_seconds >= 0),
      completed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS quiz_attempts_user_id_idx ON quiz_attempts(user_id);
  `);
  for (const [username, displayName, password] of memberAccounts) {
    await pool.query(`INSERT INTO users (email, username, display_name, password_hash) VALUES ($1, $2, $3, $4) ON CONFLICT(username) DO UPDATE SET display_name = EXCLUDED.display_name, password_hash = EXCLUDED.password_hash`, [`${username}@project.local`, username, displayName, hashPassword(password)]);
  }
}

function sendJson(response, status, payload, headers = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  response.end(JSON.stringify(payload));
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map((part) => {
    const separator = part.indexOf('=');
    return [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
  }));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; if (body.length > 10_000) request.destroy(); });
    request.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); }
    });
    request.on('error', reject);
  });
}

function encodeBase64Url(value) { return Buffer.from(value).toString('base64url'); }
function createJwt(user) {
  const header = encodeBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = encodeBase64Url(JSON.stringify({ sub: String(user.id), exp: Math.floor(Date.now() / 1000) + 28800 }));
  const content = `${header}.${payload}`;
  return `${content}.${crypto.createHmac('sha256', jwtSecret).update(content).digest('base64url')}`;
}
async function verifyJwt(token) {
  if (!token) return null;
  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) return null;
  const expected = crypto.createHmac('sha256', jwtSecret).update(`${header}.${payload}`).digest('base64url');
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.sub || data.exp <= Math.floor(Date.now() / 1000)) return null;
    const result = await pool.query('SELECT id, email, username, display_name FROM users WHERE id = $1', [Number(data.sub)]);
    return result.rows[0] || null;
  } catch { return null; }
}
async function getAuthenticatedUser(request) { return verifyJwt(parseCookies(request).project_pulse_token); }

function serveStatic(request, response) {
  const requestedPath = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
  const filePath = path.resolve(publicRoot, `.${requestedPath === '/' ? '/index.html' : requestedPath}`);
  if (!filePath.startsWith(publicRoot) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    response.writeHead(404); response.end('Not found'); return;
  }
  const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json' };
  response.writeHead(200, { 'Content-Type': `${types[path.extname(filePath)] || 'application/octet-stream'}; charset=utf-8` });
  fs.createReadStream(filePath).pipe(response);
}

const server = http.createServer(async (request, response) => {
  try {
    if (request.url === '/api/login' && request.method === 'POST') {
      const { username, password } = await readBody(request);
      const identifier = typeof username === 'string' ? username.trim() : '';
      const query = typeof password === 'string' ? await pool.query('SELECT id, email, username, display_name, password_hash FROM users WHERE username = $1', [identifier]) : { rows: [] };
      const user = query.rows[0];
      if (!user || !verifyPassword(password, user.password_hash)) {
        sendJson(response, 401, { error: 'That username or password is not recognised.' }); return;
      }
      sendJson(response, 200, { user: { email: user.email, username: user.username, displayName: user.display_name } }, { 'Set-Cookie': `project_pulse_token=${createJwt(user)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800` }); return;
    }
    if (request.url === '/api/me' && request.method === 'GET') {
      const user = await getAuthenticatedUser(request);
      if (!user) { sendJson(response, 401, { error: 'Not signed in.' }); return; }
      sendJson(response, 200, { user: { email: user.email, username: user.username, displayName: user.display_name } }); return;
    }
    if (request.url === '/api/logout' && request.method === 'POST') {
      sendJson(response, 200, { ok: true }, { 'Set-Cookie': 'project_pulse_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' }); return;
    }
    if (request.url === '/api/results' && request.method === 'POST') {
      const user = await getAuthenticatedUser(request);
      if (!user) { sendJson(response, 401, { error: 'Your session has expired.' }); return; }
      const { score, totalQuestions, durationSeconds } = await readBody(request);
      if (!Number.isInteger(score) || !Number.isInteger(totalQuestions) || !Number.isInteger(durationSeconds) || score < 0 || score > totalQuestions || totalQuestions < 1 || durationSeconds < 0) {
        sendJson(response, 400, { error: 'Invalid quiz result.' }); return;
      }
      const result = await pool.query('INSERT INTO quiz_attempts (user_id, score, total_questions, duration_seconds) VALUES ($1, $2, $3, $4) RETURNING id, completed_at', [user.id, score, totalQuestions, durationSeconds]);
      sendJson(response, 201, { result: result.rows[0] }); return;
    }
    serveStatic(request, response);
  } catch (error) {
    sendJson(response, 400, { error: error.message });
  }
});

initializeDatabase().then(() => {
  server.listen(port, () => console.log(`Project Pulse is running at http://localhost:${port}`));
}).catch((error) => {
  console.error('Local PostgreSQL connection failed:', error.message);
  process.exitCode = 1;
});
