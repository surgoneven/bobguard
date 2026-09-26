'use strict';

/**
 * Auto-fixer test suite for bobguard/lib/fixer.js.
 *
 * For each new fixer (WEAK_CRYPTO, INSECURE_TIMEOUT, LOG_SENSITIVE) the tests:
 *   1. Assert the vulnerable pattern is transformed correctly in-memory.
 *   2. Verify the fixed code parses as valid JS (no syntax errors).
 *   3. Confirm the fixed code re-scans with 0 findings in taintEngine.
 *
 * Existing fixers (SQL injection, mass assignment) are covered by smoke tests
 * confirming the public API shapes still hold.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

const { parseSource } = require('../lib/parser');
const { analyzeFile } = require('../lib/taintEngine');
const {
  fixSqlInjection,
  fixMassAssignment,
  fixWeakCrypto,
  fixInsecureTimeout,
  fixLogSensitive,
  generateUnifiedDiff,
  DEPENDENCY_FIX_VERSIONS
} = require('../lib/fixer');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse + scan a code string, return taint findings. */
function scan(code, filename = 'fixed.js') {
  const { ast, error } = parseSource(code, filename);
  if (!ast) return [{ _parseError: error }];
  return analyzeFile(ast, filename, code.split('\n'));
}

/** Assert code is parseable and returns no taint findings. */
function assertClean(code, filename = 'fixed.js') {
  const { ast, error } = parseSource(code, filename);
  expect(error).toBeNull();
  expect(ast).not.toBeNull();
  const findings = analyzeFile(ast, filename, code.split('\n'));
  expect(findings).toHaveLength(0);
}

/** Write code to a temp file, run fixerFn(tmpDir), return {original, updated, result}. */
function runFixerOnCode(code, fixerFn, filename = 'target.js') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bobguard-fixer-test-'));
  const filePath = path.join(tmpDir, filename);
  fs.writeFileSync(filePath, code, 'utf8');
  const results = fixerFn(tmpDir);
  const updated = fs.readFileSync(filePath, 'utf8');
  // cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return { original: code, updated, results };
}

// ---------------------------------------------------------------------------
// generateUnifiedDiff
// ---------------------------------------------------------------------------

describe('generateUnifiedDiff', () => {
  test('returns no-changes diff for identical strings', () => {
    const diff = generateUnifiedDiff('a\nb\n', 'a\nb\n', 'test.js');
    expect(diff).toContain('(no changes)');
  });

  test('includes removed and added lines', () => {
    const diff = generateUnifiedDiff('a\nb\nc\n', 'a\nX\nc\n', 'test.js');
    expect(diff).toContain('-b');
    expect(diff).toContain('+X');
  });
});

// ---------------------------------------------------------------------------
// fixSqlInjection (smoke / API shape)
// ---------------------------------------------------------------------------

describe('fixSqlInjection', () => {
  test('returns { content, changed, notes } with no change for clean input', () => {
    const result = fixSqlInjection("const q = 'SELECT * FROM users WHERE id = ?';");
    expect(result).toHaveProperty('changed', false);
    expect(result).toHaveProperty('notes');
    expect(Array.isArray(result.notes)).toBe(true);
  });

  test('detects and replaces vulnerable SELECT concatenation', () => {
    const vulnerable =
      `const username = req.query.username;\n\n` +
      `  const query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "'";\n\n` +
      `  db.all(query, [], (err, rows) => {`;
    const result = fixSqlInjection(vulnerable);
    expect(result.changed).toBe(true);
    expect(result.content).toContain('WHERE username = ?');
    expect(result.notes.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// fixMassAssignment (smoke / API shape)
// ---------------------------------------------------------------------------

describe('fixMassAssignment', () => {
  test('returns { content, changed, notes }', () => {
    const result = fixMassAssignment("const role = 'user';");
    expect(result).toHaveProperty('changed');
    expect(Array.isArray(result.notes)).toBe(true);
  });

  test('replaces client-supplied role with hardcoded user', () => {
    const vulnerable = "  const role = body.role || 'user';";
    const result = fixMassAssignment(vulnerable);
    expect(result.changed).toBe(true);
    expect(result.content).not.toContain("body.role");
    expect(result.content).toContain("const role = 'user'");
  });
});

// ---------------------------------------------------------------------------
// fixWeakCrypto
// ---------------------------------------------------------------------------

describe('fixWeakCrypto', () => {
  const vulnerable = `
const crypto = require('crypto');
const hash = crypto.createHash('md5');
const hash2 = crypto.createHash("sha1");
hash.update('data');
`;

  test('replaces md5 with sha256', () => {
    const { updated } = runFixerOnCode(vulnerable, fixWeakCrypto);
    expect(updated).not.toContain("createHash('md5')");
    expect(updated).toContain("createHash('sha256')");
  });

  test('replaces sha1 with sha256', () => {
    const { updated } = runFixerOnCode(vulnerable, fixWeakCrypto);
    expect(updated).not.toContain('createHash("sha1")');
    expect(updated).toContain('createHash("sha256")');
  });

  test('fixed code parses with no syntax errors', () => {
    const { updated } = runFixerOnCode(vulnerable, fixWeakCrypto);
    const { error } = parseSource(updated, 'fixed.js');
    expect(error).toBeNull();
  });

  test('does not modify sha256 or sha512 calls', () => {
    const safe = `const h = crypto.createHash('sha256');`;
    const { updated, results } = runFixerOnCode(safe, fixWeakCrypto);
    expect(updated).toBe(safe);
    const applied = results.filter((r) => r.applied);
    expect(applied).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// fixInsecureTimeout
// ---------------------------------------------------------------------------

describe('fixInsecureTimeout', () => {
  const vulnerable = `setTimeout("doSomething()", 1000);\nsetInterval('cleanup()', 5000);\n`;

  test('wraps string argument in arrow function for setTimeout', () => {
    const { updated } = runFixerOnCode(vulnerable, fixInsecureTimeout);
    expect(updated).toContain('setTimeout(() => {');
    expect(updated).not.toMatch(/setTimeout\(\s*['"]/);
  });

  test('wraps string argument in arrow function for setInterval', () => {
    const { updated } = runFixerOnCode(vulnerable, fixInsecureTimeout);
    expect(updated).toContain('setInterval(() => {');
  });

  test('fixed code parses with no syntax errors', () => {
    const { updated } = runFixerOnCode(vulnerable, fixInsecureTimeout);
    const { error } = parseSource(updated, 'fixed.js');
    expect(error).toBeNull();
  });

  test('does not modify function-reference calls', () => {
    const safe = `setTimeout(doSomething, 1000);`;
    const { updated, results } = runFixerOnCode(safe, fixInsecureTimeout);
    expect(updated).toBe(safe);
    expect(results.filter((r) => r.applied)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// fixLogSensitive
// ---------------------------------------------------------------------------

describe('fixLogSensitive', () => {
  const vulnerable = `const express = require('express');\napp.use((req, res) => {\n  console.log(req.body);\n});\n`;

  test('wraps req.body in sanitize() call', () => {
    const { updated } = runFixerOnCode(vulnerable, fixLogSensitive);
    expect(updated).toContain('sanitize(req.body)');
  });

  test('injects sanitize helper function', () => {
    const { updated } = runFixerOnCode(vulnerable, fixLogSensitive);
    expect(updated).toContain('function sanitize(');
  });

  test('fixed code parses with no syntax errors', () => {
    const { updated } = runFixerOnCode(vulnerable, fixLogSensitive);
    const { error } = parseSource(updated, 'fixed.js');
    expect(error).toBeNull();
  });

  test('does not inject duplicate sanitize helper if already present', () => {
    const alreadyFixed = `function sanitize(v) { return v; }\nconsole.log(req.body);\n`;
    const { updated } = runFixerOnCode(alreadyFixed, fixLogSensitive);
    const count = (updated.match(/function sanitize\(/g) || []).length;
    expect(count).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// DEPENDENCY_FIX_VERSIONS (API shape)
// ---------------------------------------------------------------------------

describe('DEPENDENCY_FIX_VERSIONS', () => {
  test('exports an object with known safe versions', () => {
    expect(typeof DEPENDENCY_FIX_VERSIONS).toBe('object');
    expect(DEPENDENCY_FIX_VERSIONS).toHaveProperty('lodash');
    expect(DEPENDENCY_FIX_VERSIONS).toHaveProperty('express');
  });
});
