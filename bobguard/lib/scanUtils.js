'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_IGNORE_PATTERNS = ['node_modules/', '.git/', 'dist/', 'build/', 'coverage/', '*.min.js'];
const SCANNABLE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx']);

/**
 * Converts one .gitignore/.bobignore-style pattern line into a compiled
 * matcher. Supports: leading '/' (root-anchored), trailing '/'
 * (directory-only), '*' (any run of non-'/' chars), '**' (any run of any
 * chars), '?' (single char). This is intentionally a subset of full
 * gitignore syntax - enough for the common cases these files actually use.
 * @param {string} pattern
 * @returns {{regex: RegExp, dirOnly: boolean, raw: string}|null}
 */
function globToRegExp(pattern) {
  let p = pattern.trim();
  if (!p || p.startsWith('#')) return null;

  let anchored = false;
  if (p.startsWith('/')) {
    anchored = true;
    p = p.slice(1);
  }
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);

  const escaped = p
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '.');

  const source = anchored ? `^${escaped}(?:/.*)?$` : `(^|/)${escaped}(?:/.*)?$`;
  return { regex: new RegExp(source), dirOnly, raw: pattern };
}

/**
 * Loads default ignore patterns plus anything in .gitignore and .bobignore
 * at the repo root.
 * @param {string} repoRoot
 * @returns {Array<{regex: RegExp, dirOnly: boolean, raw: string}>}
 */
function loadIgnorePatterns(repoRoot) {
  const patterns = [...DEFAULT_IGNORE_PATTERNS];

  ['.gitignore', '.bobignore'].forEach((fname) => {
    const p = path.join(repoRoot, fname);
    if (fs.existsSync(p)) {
      fs.readFileSync(p, 'utf8')
        .split(/\r?\n/)
        .forEach((line) => {
          if (line.trim() && !line.trim().startsWith('#')) patterns.push(line.trim());
        });
    }
  });

  return patterns.map(globToRegExp).filter(Boolean);
}

/**
 * @param {string} relativePath - path relative to repoRoot, any separator
 * @param {Array} compiledPatterns - from loadIgnorePatterns()
 * @returns {boolean}
 */
function isIgnored(relativePath, compiledPatterns) {
  const normalized = relativePath.split(path.sep).join('/');
  return compiledPatterns.some(({ regex }) => regex.test(normalized));
}

/**
 * Recursively lists scannable source files under a directory, skipping
 * anything matched by the compiled ignore patterns. Directory pruning
 * happens before recursing, so an ignored directory (e.g. node_modules/)
 * is never even opened.
 * @param {string} rootDir
 * @param {Array} compiledPatterns
 * @returns {string[]} absolute file paths
 */
function listScannableFiles(rootDir, compiledPatterns) {
  const results = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      return; // unreadable directory (permissions, race) - skip, don't crash the scan
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relPath = path.relative(rootDir, fullPath);

      if (isIgnored(relPath, compiledPatterns)) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (SCANNABLE_EXTENSIONS.has(path.extname(entry.name))) {
        results.push(fullPath);
      }
    }
  }

  walk(rootDir);
  return results;
}

/**
 * Bounded-concurrency task runner. Never runs more than `concurrency` tasks
 * at once, regardless of how many are queued; a rejected task does not
 * stall the rest of the queue.
 * @param {number} concurrency
 * @returns {function(function(): Promise): Promise} a `limit(fn)` function
 */
function createLimiter(concurrency) {
  let active = 0;
  const queue = [];

  function next() {
    if (active >= concurrency || queue.length === 0) return;
    active += 1;
    const { fn, resolve, reject } = queue.shift();
    Promise.resolve()
      .then(fn)
      .then(
        (val) => {
          active -= 1;
          resolve(val);
          next();
        },
        (err) => {
          active -= 1;
          reject(err);
          next();
        }
      );
  }

  return function limit(fn) {
    return new Promise((resolve, reject) => {
      queue.push({ fn, resolve, reject });
      next();
    });
  };
}

module.exports = {
  globToRegExp,
  loadIgnorePatterns,
  isIgnored,
  listScannableFiles,
  createLimiter,
  DEFAULT_IGNORE_PATTERNS,
  SCANNABLE_EXTENSIONS
};
