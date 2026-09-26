'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Attempts to parse Jest's textual summary line (works with default and
 * --verbose reporters) as a fallback when --json isn't available/parseable.
 * @param {string} output
 * @returns {{numPassedTests: number, numFailedTests: number, numTotalTests: number}}
 */
function parseJestTextSummary(output) {
  const testsLine = output.match(/Tests:\s+(.*)/);
  let passed = 0;
  let failed = 0;
  let total = 0;

  if (testsLine) {
    const segment = testsLine[1];
    const passedMatch = segment.match(/(\d+)\s+passed/);
    const failedMatch = segment.match(/(\d+)\s+failed/);
    const totalMatch = segment.match(/(\d+)\s+total/);
    if (passedMatch) passed = parseInt(passedMatch[1], 10);
    if (failedMatch) failed = parseInt(failedMatch[1], 10);
    if (totalMatch) total = parseInt(totalMatch[1], 10);
  }

  return { numPassedTests: passed, numFailedTests: failed, numTotalTests: total };
}

/**
 * Runs the target directory's test suite (`npm test`, which is expected to
 * invoke Jest per package.json) via child_process.execSync, capturing
 * stdout/stderr, pass/fail metrics, and wall-clock execution time.
 *
 * Never throws on test failure: a non-zero exit code from the test command
 * is captured as `passed: false` rather than propagating as a thrown error,
 * so callers can inspect results programmatically.
 *
 * @param {string} targetDir - directory containing package.json + tests
 * @param {object} [options]
 * @param {number} [options.timeoutMs=120000] - kill the test process after this long
 * @returns {{
 *   ran: boolean,
 *   passed: boolean,
 *   exitCode: number|null,
 *   durationMs: number,
 *   stdout: string,
 *   stderr: string,
 *   metrics: {numPassedTests: number, numFailedTests: number, numTotalTests: number},
 *   error: string|null
 * }}
 */
function runTestSuite(targetDir, options = {}) {
  const timeoutMs = options.timeoutMs || 120000;
  const resolvedDir = path.resolve(targetDir);
  const pkgPath = path.join(resolvedDir, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    return {
      ran: false,
      passed: false,
      exitCode: null,
      durationMs: 0,
      stdout: '',
      stderr: '',
      metrics: { numPassedTests: 0, numFailedTests: 0, numTotalTests: 0 },
      error: `package.json not found at ${pkgPath}`
    };
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  if (!pkg.scripts || !pkg.scripts.test) {
    return {
      ran: false,
      passed: false,
      exitCode: null,
      durationMs: 0,
      stdout: '',
      stderr: '',
      metrics: { numPassedTests: 0, numFailedTests: 0, numTotalTests: 0 },
      error: `No "test" script defined in ${pkgPath}`
    };
  }

  const startedAt = Date.now();
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let execError = null;

  try {
    stdout = execSync('npm test', {
      cwd: resolvedDir,
      timeout: timeoutMs,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: Object.assign({}, process.env, { CI: 'true' })
    });
  } catch (err) {
    // execSync throws on non-zero exit; the failure output is still useful.
    stdout = err.stdout ? err.stdout.toString() : '';
    stderr = err.stderr ? err.stderr.toString() : '';
    exitCode = typeof err.status === 'number' ? err.status : 1;
    if (err.signal) {
      execError = `Process terminated by signal ${err.signal} (possible timeout)`;
    }
  }

  const durationMs = Date.now() - startedAt;
  const combinedOutput = `${stdout}\n${stderr}`;
  const metrics = parseJestTextSummary(combinedOutput);

  return {
    ran: true,
    passed: exitCode === 0,
    exitCode,
    durationMs,
    stdout,
    stderr,
    metrics,
    error: execError
  };
}

/**
 * Compares a "before fix" and "after fix" test run to determine whether
 * applying auto-fixes broke any previously-passing tests.
 * @param {object} beforeResult - output of runTestSuite() pre-fix
 * @param {object} afterResult - output of runTestSuite() post-fix
 * @returns {{regressed: boolean, details: string}}
 */
function detectRegression(beforeResult, afterResult) {
  if (!beforeResult.ran || !afterResult.ran) {
    return { regressed: false, details: 'One or both test runs did not execute; regression check skipped.' };
  }

  const before = beforeResult.metrics;
  const after = afterResult.metrics;

  if (beforeResult.passed && !afterResult.passed) {
    return {
      regressed: true,
      details: `Suite passed before fixes (${before.numPassedTests}/${before.numTotalTests}) but failed after fixes (${after.numPassedTests}/${after.numTotalTests}).`
    };
  }

  if (after.numPassedTests < before.numPassedTests) {
    return {
      regressed: true,
      details: `Passing test count dropped after fixes: ${before.numPassedTests} -> ${after.numPassedTests}.`
    };
  }

  return {
    regressed: false,
    details: `No regression detected. Before: ${before.numPassedTests}/${before.numTotalTests} passed. After: ${after.numPassedTests}/${after.numTotalTests} passed.`
  };
}

module.exports = {
  runTestSuite,
  detectRegression,
  parseJestTextSummary
};
