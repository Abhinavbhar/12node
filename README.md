# Node.js built-in HTTP + SQLite

Minimal reference implementation for the $12 Server Challenge.

- Runtime: Node.js
- HTTP: built-in `node:http`
- JWT: built-in `node:crypto` (HS256 verification)
- SQLite: `better-sqlite3` 11.8.1
- No framework, ORM, cache, or external service
- Direct HTTP/1.1 with keep-alive

## Build and run

```bash
bash install.sh
bash build.sh
SQLITE_PATH=/absolute/path/to/feed.db \
JWT_SECRET=twelve-dollar-challenge \
HOST=0.0.0.0 PORT=8080 \
bash start.sh
```

From the repository root, correctness-test with:

```bash
bash test/run.sh submissions/node-http-yourname
```

This is intentionally a simple baseline, not an optimized implementation. SQLite calls are synchronous and execute on the Node event loop. Every request reads from SQLite; JWT signatures are verified on every authenticated request. Writes return only after the SQLite statement completes.

SQLite is configured for WAL, `synchronous=NORMAL`, foreign keys, and a 5-second busy timeout.
