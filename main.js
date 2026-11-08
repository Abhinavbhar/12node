#!/usr/bin/env node
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const Database = require('better-sqlite3');

const SQLITE_PATH = process.env.SQLITE_PATH;
const JWT_SECRET = process.env.JWT_SECRET;
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);

if (!SQLITE_PATH || !JWT_SECRET) {
  console.error('SQLITE_PATH and JWT_SECRET environment variables are required');
  process.exit(1);
}

const startedAt = Date.now();
const db = new Database(SQLITE_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

const qHealth = db.prepare('SELECT 1 AS ok');
const qFeed = db.prepare(`
  SELECT p.id, p.body, p.created_at, u.username AS author,
         (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count
    FROM posts p
    JOIN users u ON u.id = p.user_id
   ORDER BY p.created_at DESC, p.id DESC
   LIMIT 20
`);
const qPost = db.prepare(`
  SELECT p.id, p.body, p.created_at, u.username AS author,
         (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count
    FROM posts p
    JOIN users u ON u.id = p.user_id
   WHERE p.id = ?
`);
const qInsertPost = db.prepare('INSERT INTO posts (user_id, body) VALUES (?, ?)');
const qInsertLike = db.prepare(
  'INSERT INTO likes (user_id, post_id) VALUES (?, ?) ON CONFLICT (user_id, post_id) DO NOTHING'
);
const qPostExists = db.prepare('SELECT 1 FROM posts WHERE id = ?');

function send(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function fail(res, status, message) {
  send(res, status, { error: message });
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('bad base64url');
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function authenticate(req, res) {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    fail(res, 401, 'missing bearer token');
    return null;
  }

  const token = header.slice(7);
  try {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('malformed JWT');

    const headerPart = JSON.parse(decodeBase64Url(parts[0]).toString('utf8'));
    const payload = JSON.parse(decodeBase64Url(parts[1]).toString('utf8'));
    if (!headerPart || headerPart.alg !== 'HS256') throw new Error('wrong algorithm');

    const supplied = decodeBase64Url(parts[2]);
    const expected = crypto.createHmac('sha256', JWT_SECRET)
      .update(`${parts[0]}.${parts[1]}`)
      .digest();

    if (supplied.length !== expected.length ||
        !crypto.timingSafeEqual(supplied, expected)) {
      throw new Error('bad signature');
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || now >= payload.exp) {
      throw new Error('expired');
    }
    if (payload.nbf !== undefined &&
        (typeof payload.nbf !== 'number' || now < payload.nbf)) {
      throw new Error('not active');
    }

    if (typeof payload.sub !== 'string' ||
        !/^[1-9][0-9]*$/.test(payload.sub) ||
        !Number.isSafeInteger(Number(payload.sub)) ||
        typeof payload.username !== 'string') {
      fail(res, 401, 'invalid token payload');
      return null;
    }

    return { userId: Number(payload.sub), username: payload.username };
  } catch {
    fail(res, 401, 'invalid or expired token');
    return null;
  }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', chunk => {
      data += chunk;
      if (Buffer.byteLength(data, 'utf8') > 16384) {
        reject(new Error('body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new SyntaxError('malformed JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function parsePostId(raw) {
  if (!/^[1-9][0-9]*$/.test(raw)) return null;
  const id = Number(raw);
  return Number.isSafeInteger(id) ? id : null;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname;

    if (req.method === 'GET' && path === '/health') {
      try {
        qHealth.get();
        return send(res, 200, {
          status: 'ok',
          db: 'ok',
          uptime_s: Math.floor((Date.now() - startedAt) / 1000),
        });
      } catch (err) {
        return send(res, 503, {
          status: 'degraded',
          db: 'unreachable',
          error: String(err.message || err),
        });
      }
    }

    if (req.method === 'GET' && path === '/feed') {
      return send(res, 200, { posts: qFeed.all() });
    }

    const postMatch = path.match(/^\/posts\/([^/]+)$/);
    if (req.method === 'GET' && postMatch) {
      const id = parsePostId(postMatch[1]);
      if (id === null) return fail(res, 400, 'invalid post id');
      const post = qPost.get(id);
      if (!post) return fail(res, 404, 'post not found');
      return send(res, 200, { post });
    }

    if (req.method === 'POST' && path === '/posts') {
      const user = authenticate(req, res);
      if (!user) return;
      let input;
      try {
        input = await readJson(req);
      } catch (err) {
        return fail(res, 400, err instanceof SyntaxError ? 'malformed JSON body' : 'malformed JSON body');
      }
      if (!input || typeof input.body !== 'string') {
        return fail(res, 400, 'body is required');
      }
      const body = input.body.trim();
      if (!body) return fail(res, 400, 'body is required');
      if (Array.from(body).length > 500) {
        return fail(res, 400, 'body must be at most 500 characters');
      }

      const result = qInsertPost.run(user.userId, body);
      const post = qPost.get(Number(result.lastInsertRowid));
      return send(res, 201, { post });
    }

    const likeMatch = path.match(/^\/posts\/([^/]+)\/like$/);
    if (req.method === 'POST' && likeMatch) {
      const user = authenticate(req, res);
      if (!user) return;

      const id = parsePostId(likeMatch[1]);
      if (id === null) return fail(res, 400, 'invalid post id');
      if (!qPostExists.get(id)) return fail(res, 404, 'post not found');

      const result = qInsertLike.run(user.userId, id);
      const alreadyLiked = result.changes === 0;
      return send(res, alreadyLiked ? 200 : 201, {
        liked: true,
        already_liked: alreadyLiked,
        post_id: id,
      });
    }

    return fail(res, 404, 'not found');
  } catch (err) {
    if (!res.headersSent) fail(res, 500, 'internal server error');
    else res.destroy();
    console.error(err);
  }
});

server.keepAliveTimeout = 70000;
server.headersTimeout = 75000;
server.requestTimeout = 75000;

server.listen(PORT, HOST, () => {
  console.log(`Node HTTP server listening on ${HOST}:${PORT}`);
});

function shutdown() {
  server.close(() => {
    try { db.close(); } finally { process.exit(0); }
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
