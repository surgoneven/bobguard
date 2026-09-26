'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// In-memory SQLite DB seeded with demo users
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)');
  db.run("INSERT INTO users (username, email, role) VALUES ('admin', 'admin@demo.local', 'admin')");
  db.run("INSERT INTO users (username, email, role) VALUES ('alice', 'alice@demo.local', 'user')");
  db.run("INSERT INTO users (username, email, role) VALUES ('bob', 'bob@demo.local', 'user')");
});

// Input validation helpers
const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const POSITIVE_INT_PATTERN = /^[1-9][0-9]*$/;

/**
 * Validates the `username` query parameter for GET /api/users/search.
 * @param {object} query
 * @returns {{present: boolean, valid: boolean, value: (string|null)}}
 */
function validateUsernameQueryParam(query) {
  const raw = query ? query.username : undefined;

  if (raw === undefined) {
    return { present: false, valid: true, value: null };
  }
  if (typeof raw !== 'string') {
    return { present: true, valid: false, value: null };
  }

  const trimmed = raw.trim();
  if (!USERNAME_PATTERN.test(trimmed)) {
    return { present: true, valid: false, value: null };
  }

  return { present: true, valid: true, value: trimmed };
}

/**
 * Validates the JSON body for POST /api/users.
 * @param {object} body
 * @returns {{valid: boolean, username?: string, email?: string, error?: string}}
 */
function validateCreateUserPayload(body) {
  const safeBody = body && typeof body === 'object' ? body : {};
  const rawUsername = safeBody.username;
  const rawEmail = safeBody.email;

  if (typeof rawUsername !== 'string' || typeof rawEmail !== 'string') {
    return { valid: false, error: 'username and email are required strings' };
  }

  const username = rawUsername.trim();
  const email = rawEmail.trim();

  if (!USERNAME_PATTERN.test(username)) {
    return {
      valid: false,
      error: 'username must be 1-64 characters of letters, numbers, "_", "." or "-"'
    };
  }
  if (!EMAIL_PATTERN.test(email)) {
    return { valid: false, error: 'email must be a valid email address' };
  }

  return { valid: true, username, email };
}

/**
 * Validates the `:id` route parameter as a positive integer.
 * @param {*} rawId
 * @returns {{valid: boolean, id?: number}}
 */
function parseUserIdParam(rawId) {
  if (typeof rawId !== 'string' || !POSITIVE_INT_PATTERN.test(rawId)) {
    return { valid: false };
  }
  return { valid: true, id: Number(rawId) };
}

/** GET /api/users/search?username=<name> */
app.get('/api/users/search', (req, res) => {
  const usernameCheck = validateUsernameQueryParam(req.query);

  if (!usernameCheck.present) {
    return res.status(200).json({ results: [] });
  }
  if (!usernameCheck.valid) {
    return res.status(400).json({
      error: 'username must be 1-64 characters of letters, numbers, "_", "." or "-"'
    });
  }

  const query = 'SELECT id, username, email, role FROM users WHERE username = ?';

  db.all(query, [usernameCheck.value], (err, rows) => {
    if (err) {
      console.error('Internal Error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    return res.status(200).json({ results: rows });
  });
});

/** POST /api/users */
app.post('/api/users', (req, res) => {
  const validation = validateCreateUserPayload(req.body);

  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { username, email } = validation;

  const role = 'user';

  const insertQuery = 'INSERT INTO users (username, email, role) VALUES (?, ?, ?)';

  db.run(insertQuery, [username, email, role], function (err) {
    if (err) {
      console.error('Internal Error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    return res.status(201).json({
      id: this.lastID,
      username: username,
      email: email,
      role: role
    });
  });
});

/** GET /api/users/:id */
app.get('/api/users/:id', (req, res) => {
  const idCheck = parseUserIdParam(req.params.id);

  if (!idCheck.valid) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }

  db.get('SELECT id, username, email, role FROM users WHERE id = ?', [idCheck.id], (err, row) => {
    if (err) {
      console.error('Internal Error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.status(200).json({ result: row });
  });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`demo-app listening on port ${PORT}`);
  });
}

module.exports = { app, db };