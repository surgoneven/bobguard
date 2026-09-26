'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Minimal unified-diff generator (Myers-style LCS) so we don't depend on an
 * external diff package. Good enough for file-sized text, not built for huge
 * inputs.
 * @param {string} oldText
 * @param {string} newText
 * @param {string} label - display name for the diff header (relative path)
 * @returns {string} unified diff text
 */
function generateUnifiedDiff(oldText, newText, label) {
  const oldLines = oldText.split(/\r?\n/);
  const newLines = newText.split(/\r?\n/);

  const m = oldLines.length;
  const n = newLines.length;

  // LCS length table
  const lcs = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (oldLines[i] === newLines[j]) {
        lcs[i][j] = lcs[i + 1][j + 1] + 1;
      } else {
        lcs[i][j] = Math.max(lcs[i + 1][j], lcs[i][j + 1]);
      }
    }
  }

  // Walk the table to build an op list: 'equal' | 'delete' | 'insert'
  const ops = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (oldLines[i] === newLines[j]) {
      ops.push({ type: 'equal', line: oldLines[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push({ type: 'delete', line: oldLines[i] });
      i++;
    } else {
      ops.push({ type: 'insert', line: newLines[j] });
      j++;
    }
  }
  while (i < m) {
    ops.push({ type: 'delete', line: oldLines[i] });
    i++;
  }
  while (j < n) {
    ops.push({ type: 'insert', line: newLines[j] });
    j++;
  }

  // Group ops into hunks with 3 lines of context, unified-diff style.
  const CONTEXT = 3;
  const hunks = [];
  let k = 0;
  while (k < ops.length) {
    if (ops[k].type === 'equal') {
      k++;
      continue;
    }
    let start = Math.max(0, k - CONTEXT);
    let end = k;
    while (end < ops.length) {
      if (ops[end].type !== 'equal') {
        end++;
        continue;
      }
      let lookahead = end;
      while (lookahead < ops.length && ops[lookahead].type === 'equal' && lookahead - end < CONTEXT * 2) {
        lookahead++;
      }
      if (lookahead - end >= CONTEXT || lookahead === ops.length) {
        end = Math.min(ops.length, end + CONTEXT);
        break;
      }
      end = lookahead;
    }
    hunks.push(ops.slice(start, end));
    k = end;
  }

  if (hunks.length === 0) {
    return `--- a/${label}\n+++ b/${label}\n(no changes)\n`;
  }

  let oldLineNo = 1;
  let newLineNo = 1;
  let diffText = `--- a/${label}\n+++ b/${label}\n`;

  // Recompute per-hunk starting line numbers by scanning ops from the start.
  let cursor = 0;
  for (const hunk of hunks) {
    const hunkStartIdx = ops.indexOf(hunk[0], cursor);
    let oStart = 1;
    let nStart = 1;
    let oCount = 0;
    let nCount = 0;
    for (let x = 0; x < hunkStartIdx; x++) {
      if (ops[x].type !== 'insert') oStart++;
      if (ops[x].type !== 'delete') nStart++;
    }
    hunk.forEach((op) => {
      if (op.type !== 'insert') oCount++;
      if (op.type !== 'delete') nCount++;
    });

    diffText += `@@ -${oStart},${oCount} +${nStart},${nCount} @@\n`;
    hunk.forEach((op) => {
      if (op.type === 'equal') diffText += ` ${op.line}\n`;
      else if (op.type === 'delete') diffText += `-${op.line}\n`;
      else diffText += `+${op.line}\n`;
    });
    cursor = hunkStartIdx + hunk.length;
  }

  return diffText;
}

/**
 * Fixes the SQL-injection finding in server.js:
 *  - GET /api/users/search: string-concatenated SELECT -> parameterized query
 *  - POST /api/users: string-concatenated INSERT -> parameterized query
 * @param {string} content - original server.js source
 * @returns {{content: string, changed: boolean, notes: string[]}}
 */
function fixSqlInjection(content) {
  let updated = content;
  const notes = [];

  const vulnerableSearchBlock =
    `const username = req.query.username;\n\n` +
    `  const query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "'";\n\n` +
    `  db.all(query, [], (err, rows) => {`;

  const fixedSearchBlock =
    `const username = req.query.username;\n\n` +
    `  const query = 'SELECT id, username, email, role FROM users WHERE username = ?';\n\n` +
    `  db.all(query, [username], (err, rows) => {`;

  if (updated.includes(vulnerableSearchBlock)) {
    updated = updated.replace(vulnerableSearchBlock, fixedSearchBlock);
    notes.push('GET /api/users/search: replaced string-concatenated SELECT with parameterized query (? placeholder).');
  }

  const vulnerableInsertBlock =
    `const insertQuery = "INSERT INTO users (username, email, role) VALUES ('" +\n` +
    `    username + "', '" + email + "', '" + role + "')";\n\n` +
    `  db.run(insertQuery, function (err) {`;

  const fixedInsertBlock =
    `const insertQuery = 'INSERT INTO users (username, email, role) VALUES (?, ?, ?)';\n\n` +
    `  db.run(insertQuery, [username, email, role], function (err) {`;

  if (updated.includes(vulnerableInsertBlock)) {
    updated = updated.replace(vulnerableInsertBlock, fixedInsertBlock);
    notes.push('POST /api/users: replaced string-concatenated INSERT with parameterized query (? placeholders).');
  }

  return { content: updated, changed: updated !== content, notes };
}

/**
 * Fixes the mass-assignment finding in server.js: the POST /api/users
 * handler no longer trusts a client-supplied 'role' field. Role is always
 * forced to 'user'; privilege changes must go through a separate,
 * authorization-checked admin endpoint (not in scope for this demo).
 * @param {string} content
 * @returns {{content: string, changed: boolean, notes: string[]}}
 */
function fixMassAssignment(content) {
  let updated = content;
  const notes = [];

  const vulnerableRoleLine = `  const role = body.role || 'user';`;
  const fixedRoleBlock =
    `  // SECURITY: 'role' is never taken from client input (prevents\n` +
    `  // privilege-escalation via mass assignment). Only an authenticated\n` +
    `  // admin workflow may change a user's role.\n` +
    `  const role = 'user';`;

  if (updated.includes(vulnerableRoleLine)) {
    updated = updated.replace(vulnerableRoleLine, fixedRoleBlock);
    notes.push("POST /api/users: 'role' field is no longer accepted from the request body; always defaults to 'user' (mass-assignment fix).");
  }

  const vulnerableInputBlock =
    `  const body = req.body;\n\n` +
    `  const username = body.username;\n` +
    `  const email = body.email;`;

  const fixedInputBlock =
    `  const body = req.body || {};\n\n` +
    `  const username = typeof body.username === 'string' ? body.username.trim() : '';\n` +
    `  const email = typeof body.email === 'string' ? body.email.trim() : '';\n\n` +
    `  if (!username || !email) {\n` +
    `    return res.status(400).json({ error: 'username and email are required strings' });\n` +
    `  }`;

  if (updated.includes(vulnerableInputBlock)) {
    updated = updated.replace(vulnerableInputBlock, fixedInputBlock);
    notes.push('POST /api/users: added input whitelisting/type validation for username and email (rejects missing/non-string values).');
  }

  return { content: updated, changed: updated !== content, notes };
}

/**
 * Applies all server.js fixes and writes the result to disk.
 * @param {string} targetDir - demo-app directory containing server.js
 * @returns {{filePath: string, applied: boolean, notes: string[], diff: string}}
 */
function fixServerFile(targetDir) {
  const filePath = path.join(targetDir, 'server.js');
  if (!fs.existsSync(filePath)) {
    return { filePath, applied: false, notes: [`server.js not found at ${filePath}`], diff: '' };
  }

  const original = fs.readFileSync(filePath, 'utf8');

  const sqlResult = fixSqlInjection(original);
  const massAssignResult = fixMassAssignment(sqlResult.content);

  const finalContent = massAssignResult.content;
  const allNotes = [...sqlResult.notes, ...massAssignResult.notes];
  const applied = finalContent !== original;

  if (applied) {
    fs.writeFileSync(filePath, finalContent, 'utf8');
  }

  const diff = generateUnifiedDiff(original, finalContent, path.relative(process.cwd(), filePath) || 'server.js');

  return { filePath, applied, notes: allNotes, diff };
}

/** Known safe target versions to bump vulnerable packages to. */
const DEPENDENCY_FIX_VERSIONS = {
  lodash: '4.17.21',
  express: '4.17.3',
  'body-parser': '1.20.3',
  minimist: '1.2.6'
};

/**
 * Bumps vulnerable dependency versions in package.json, preserving the
 * original semver range prefix (^, ~, or none).
 * @param {string} targetDir - directory containing package.json
 * @returns {{filePath: string, applied: boolean, notes: string[], diff: string}}
 */
function fixDependencies(targetDir) {
  const filePath = path.join(targetDir, 'package.json');
  if (!fs.existsSync(filePath)) {
    return { filePath, applied: false, notes: [`package.json not found at ${filePath}`], diff: '' };
  }

  const original = fs.readFileSync(filePath, 'utf8');
  const pkg = JSON.parse(original);
  const notes = [];

  ['dependencies', 'devDependencies'].forEach((depField) => {
    if (!pkg[depField]) return;
    Object.keys(pkg[depField]).forEach((name) => {
      const fixVersion = DEPENDENCY_FIX_VERSIONS[name];
      if (!fixVersion) return;

      const currentDeclared = pkg[depField][name];
      const prefixMatch = currentDeclared.match(/^([\^~]?)/);
      const prefix = prefixMatch ? prefixMatch[1] : '';
      const newDeclared = `${prefix}${fixVersion}`;

      if (currentDeclared !== newDeclared) {
        pkg[depField][name] = newDeclared;
        notes.push(`${name}: ${currentDeclared} -> ${newDeclared}`);
      }
    });
  });

  const updated = JSON.stringify(pkg, null, 2) + '\n';
  const applied = updated !== original;

  if (applied) {
    fs.writeFileSync(filePath, updated, 'utf8');
  }

  const diff = generateUnifiedDiff(original, updated, path.relative(process.cwd(), filePath) || 'package.json');

  return { filePath, applied, notes, diff };
}

// ---------------------------------------------------------------------------
// New rule fixers: WEAK_CRYPTO, INSECURE_TIMEOUT, LOG_SENSITIVE
// ---------------------------------------------------------------------------

/**
 * Fixes WEAK_CRYPTO findings: replaces `crypto.createHash('md5')` and
 * `crypto.createHash('sha1')` with `crypto.createHash('sha256')` across all
 * .js / .ts source files in the target directory.
 *
 * Only performs literal string argument replacement (single and double quotes,
 * case-insensitive) – safe to apply automatically.
 *
 * @param {string} targetDir
 * @returns {{filePath: string, applied: boolean, notes: string[], diff: string}[]}
 */
function fixWeakCrypto(targetDir) {
  const results = [];
  const exts = ['.js', '.ts', '.mjs', '.cjs'];
  const WEAK_HASH_RE = /crypto\.createHash\(\s*(['"])(md5|sha1|sha-1)\1\s*\)/gi;

  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.forEach((e) => {
      if (e.isDirectory() && e.name !== 'node_modules' && !e.name.startsWith('.')) {
        walk(path.join(dir, e.name));
      } else if (e.isFile() && exts.includes(path.extname(e.name))) {
        const filePath = path.join(dir, e.name);
        let original;
        try { original = fs.readFileSync(filePath, 'utf8'); } catch { return; }

        const updated = original.replace(WEAK_HASH_RE, (match, q, algo) =>
          `crypto.createHash(${q}sha256${q})`
        );

        const changed = updated !== original;
        const notes = [];
        if (changed) {
          fs.writeFileSync(filePath, updated, 'utf8');
          const matchCount = (original.match(WEAK_HASH_RE) || []).length;
          notes.push(`${path.relative(targetDir, filePath)}: replaced ${matchCount} weak hash call(s) (md5/sha1 -> sha256).`);
        }
        const diff = generateUnifiedDiff(original, updated, path.relative(process.cwd(), filePath).replace(/\\/g, '/'));
        results.push({ filePath, applied: changed, notes, diff });
      }
    });
  }

  walk(targetDir);
  return results;
}

/**
 * Fixes INSECURE_TIMEOUT findings: converts string-based setTimeout/setInterval
 * calls into arrow-function wrappers.
 *
 * Pattern: `setTimeout("code", ms)` -> `setTimeout(() => { code }, ms)`
 *
 * @param {string} targetDir
 * @returns {{filePath: string, applied: boolean, notes: string[], diff: string}[]}
 */
function fixInsecureTimeout(targetDir) {
  const results = [];
  const exts = ['.js', '.ts', '.mjs', '.cjs'];
  // Match setTimeout/setInterval with a string as first arg (single or double quote)
  const TIMEOUT_STRING_RE = /\b(setTimeout|setInterval)\(\s*(['"`])([\s\S]*?)\2\s*,/g;

  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.forEach((e) => {
      if (e.isDirectory() && e.name !== 'node_modules' && !e.name.startsWith('.')) {
        walk(path.join(dir, e.name));
      } else if (e.isFile() && exts.includes(path.extname(e.name))) {
        const filePath = path.join(dir, e.name);
        let original;
        try { original = fs.readFileSync(filePath, 'utf8'); } catch { return; }

        const updated = original.replace(TIMEOUT_STRING_RE, (match, fn, q, code) =>
          `${fn}(() => { ${code} },`
        );

        const changed = updated !== original;
        const notes = [];
        if (changed) {
          fs.writeFileSync(filePath, updated, 'utf8');
          notes.push(`${path.relative(targetDir, filePath)}: wrapped string argument(s) in ${
            updated.match(/\b(setTimeout|setInterval)\(\s*\(\s*\)\s*=>/g)?.length || '?'
          } setTimeout/setInterval call(s) with arrow function.`);
        }
        const diff = generateUnifiedDiff(original, updated, path.relative(process.cwd(), filePath).replace(/\\/g, '/'));
        results.push({ filePath, applied: changed, notes, diff });
      }
    });
  }

  walk(targetDir);
  return results;
}

/**
 * Fixes LOG_SENSITIVE findings: wraps raw `req.body`, `req.query`, `req.params`,
 * and common sensitive field names in a `sanitize(...)` call inside console.* calls.
 *
 * Inserts a `function sanitize(v) { ... }` helper at the top of each modified file
 * if one is not already present.
 *
 * @param {string} targetDir
 * @returns {{filePath: string, applied: boolean, notes: string[], diff: string}[]}
 */
function fixLogSensitive(targetDir) {
  const results = [];
  const exts = ['.js', '.ts', '.mjs', '.cjs'];

  // Match console.*(... req.body / req.query / req.params / password / token ...)
  // This regex captures the whole console.xxx( call up to a closing ), wrapping the argument.
  const SENSITIVE_ARG_RE = /\b(console\.\w+)\(\s*(req\.(?:body|query|params|headers)|[^)]*?\b(?:password|token|authorization|secret)\b[^)]*?)\s*\)/g;

  const SANITIZE_HELPER = `
// Redacts sensitive fields before logging to prevent credential leakage.
function sanitize(v) {
  if (v && typeof v === 'object') {
    const safe = Object.assign({}, v);
    ['password', 'token', 'secret', 'authorization'].forEach((k) => {
      if (k in safe) safe[k] = '[REDACTED]';
    });
    return safe;
  }
  return '[REDACTED]';
}
`;

  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.forEach((e) => {
      if (e.isDirectory() && e.name !== 'node_modules' && !e.name.startsWith('.')) {
        walk(path.join(dir, e.name));
      } else if (e.isFile() && exts.includes(path.extname(e.name))) {
        const filePath = path.join(dir, e.name);
        let original;
        try { original = fs.readFileSync(filePath, 'utf8'); } catch { return; }

        let updated = original.replace(SENSITIVE_ARG_RE, (match, consoleFn, arg) =>
          `${consoleFn}(sanitize(${arg}))`
        );

        // Inject helper if not already present and changes were made
        if (updated !== original && !updated.includes('function sanitize(')) {
          updated = SANITIZE_HELPER + updated;
        }

        const changed = updated !== original;
        const notes = [];
        if (changed) {
          fs.writeFileSync(filePath, updated, 'utf8');
          notes.push(`${path.relative(targetDir, filePath)}: wrapped sensitive console log argument(s) with sanitize() helper.`);
        }
        const diff = generateUnifiedDiff(original, updated, path.relative(process.cwd(), filePath).replace(/\\/g, '/'));
        results.push({ filePath, applied: changed, notes, diff });
      }
    });
  }

  walk(targetDir);
  return results;
}

/**
 * Runs the full auto-fix pipeline against a target microservice directory.
 * Applies: SQLi, mass assignment, dependency bumps, weak crypto, insecure
 * timeout, and sensitive log argument fixes.
 * @param {string} targetDir
 * @returns {{summary: {filesChanged: number, notes: string[]}, results: object[], combinedDiff: string}}
 */
function runAutoFix(targetDir) {
  const serverResult = fixServerFile(targetDir);
  const depResult = fixDependencies(targetDir);
  const weakCryptoResults = fixWeakCrypto(targetDir);
  const timeoutResults = fixInsecureTimeout(targetDir);
  const logResults = fixLogSensitive(targetDir);

  const results = [serverResult, depResult, ...weakCryptoResults, ...timeoutResults, ...logResults];
  const filesChanged = results.filter((r) => r.applied).length;
  const notes = results.reduce((acc, r) => acc.concat(r.notes), []);
  const combinedDiff = results
    .filter((r) => r.applied)
    .map((r) => r.diff)
    .join('\n');

  return {
    summary: { filesChanged, notes },
    results,
    combinedDiff
  };
}

module.exports = {
  generateUnifiedDiff,
  fixSqlInjection,
  fixMassAssignment,
  fixServerFile,
  fixDependencies,
  fixWeakCrypto,
  fixInsecureTimeout,
  fixLogSensitive,
  runAutoFix,
  DEPENDENCY_FIX_VERSIONS
};
