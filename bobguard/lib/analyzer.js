'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Known vulnerable package versions (demo dataset, mimics an npm-audit-style
 * advisory feed). Real implementation would call the npm/OSV/Snyk API.
 */
const VULNERABLE_PACKAGES = {
  lodash: {
    ranges: [{ lt: '4.17.21', advisory: 'Prototype Pollution', severity: 'HIGH', cve: 'CVE-2020-8203' }]
  },
  express: {
    ranges: [{ lt: '4.17.3', advisory: 'Open Redirect / ReDoS in query parser', severity: 'MEDIUM', cve: 'CVE-2022-24999' }]
  },
  'body-parser': {
    ranges: [{ lt: '1.20.3', advisory: 'Denial of Service via crafted body', severity: 'MEDIUM', cve: 'CVE-2024-45590' }]
  },
  sqlite3: {
    ranges: [{ lt: '5.0.0', advisory: 'Outdated native bindings, unmaintained release line', severity: 'LOW', cve: null }]
  },
  minimist: {
    ranges: [{ lt: '1.2.6', advisory: 'Prototype Pollution', severity: 'HIGH', cve: 'CVE-2021-44906' }]
  }
};

function versionLessThan(a, b) {
  const cleanA = String(a).replace(/^[^\d]*/, '').split('.').map(Number);
  const cleanB = String(b).replace(/^[^\d]*/, '').split('.').map(Number);
  for (let i = 0; i < Math.max(cleanA.length, cleanB.length); i++) {
    const x = cleanA[i] || 0;
    const y = cleanB[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

/**
 * Scans a package.json's dependencies and devDependencies against the known
 * vulnerable package table.
 * @param {string} targetDir - directory containing package.json
 * @returns {{scanned: number, findings: Array<object>}}
 */
function analyzeDependencies(targetDir) {
  const pkgPath = path.join(targetDir, 'package.json');
  const findings = [];

  if (!fs.existsSync(pkgPath)) {
    return { scanned: 0, findings, error: `package.json not found at ${pkgPath}` };
  }

  const pkgRaw = fs.readFileSync(pkgPath, 'utf8');
  const pkg = JSON.parse(pkgRaw);

  const allDeps = Object.assign({}, pkg.dependencies || {}, pkg.devDependencies || {});
  const depNames = Object.keys(allDeps);

  depNames.forEach((name) => {
    const declaredVersion = allDeps[name];
    const advisoryEntry = VULNERABLE_PACKAGES[name];
    if (!advisoryEntry) return;

    advisoryEntry.ranges.forEach((range) => {
      if (versionLessThan(declaredVersion, range.lt)) {
        findings.push({
          type: 'DEPENDENCY',
          package: name,
          declaredVersion,
          vulnerableBelow: range.lt,
          severity: range.severity,
          cve: range.cve,
          advisory: range.advisory
        });
      }
    });
  });

  return { scanned: depNames.length, findings };
}

/** File extensions considered for static source scanning. */
const SCANNABLE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx']);
const IGNORED_DIRS = new Set(['node_modules', '.git', 'coverage', 'dist', 'build']);

/**
 * Recursively collects source files under a directory, honoring a simple
 * ignore list (mirrors .bobignore semantics at a basic level).
 * @param {string} dir
 * @param {string[]} acc
 * @returns {string[]}
 */
function collectSourceFiles(dir, acc = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  entries.forEach((entry) => {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) {
        collectSourceFiles(fullPath, acc);
      }
      return;
    }

    const ext = path.extname(entry.name);
    if (SCANNABLE_EXTENSIONS.has(ext)) {
      acc.push(fullPath);
    }
  });

  return acc;
}

/**
 * Reads every scannable source file under targetDir.
 * @param {string} targetDir
 * @returns {Array<{filePath: string, content: string, lines: string[]}>}
 */
function readSourceFiles(targetDir) {
  if (!fs.existsSync(targetDir)) {
    return [];
  }
  const files = collectSourceFiles(targetDir);
  return files.map((filePath) => {
    const content = fs.readFileSync(filePath, 'utf8');
    return {
      filePath,
      content,
      lines: content.split(/\r?\n/)
    };
  });
}

module.exports = {
  analyzeDependencies,
  readSourceFiles,
  collectSourceFiles,
  versionLessThan,
  VULNERABLE_PACKAGES
};