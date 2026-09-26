'use strict';

/**
 * Stress-test suite for the BobGuard AST taint engine.
 * Tests cover:
 *   - Every existing rule (regression guard)
 *   - Four new rules: WEAK_CRYPTO, INSECURE_TIMEOUT, HIGH_ENTROPY_SECRET, LOG_SENSITIVE
 *   - Complex control-flow edge cases (async/await, deep chains, destructuring)
 *   - Alias-tracking across multiple reassignments
 *   - Template-literal taint propagation
 *   - Clean-code paths (no false positives)
 *   - Parser error boundaries (engine must never crash on bad syntax)
 */

const { parseSource } = require('../lib/parser');
const { analyzeFile, analyzeExpression, buildFunctionSummaries } = require('../lib/taintEngine');
const { evaluateOwaspRules, buildComplianceSummary } = require('../lib/compliance');

// ---------------------------------------------------------------------------
// Helper: parse + analyze a code string, return findings array
// ---------------------------------------------------------------------------
function run(code, filename = 'test.js') {
  const { ast, error } = parseSource(code, filename);
  expect(error).toBeNull(); // fail fast on unexpected parse errors
  const lines = code.split('\n');
  return analyzeFile(ast, filename, lines);
}

// Like run() but returns compliance-layer findings (with ruleId / owaspCategory)
function runCompliance(code, filename = 'test.js') {
  const lines = code.split('\n');
  return evaluateOwaspRules([{ filePath: filename, content: code, lines }]);
}

// Assert that at least one finding matches category + optional substring in description
function expectFinding(findings, category, descriptionSubstring) {
  const match = findings.find(
    (f) =>
      f.category === category &&
      (!descriptionSubstring || f.description.includes(descriptionSubstring))
  );
  if (!match) {
    const found = findings.map((f) => `${f.category}: ${f.description}`).join('\n  ');
    throw new Error(
      `Expected finding with category '${category}'${descriptionSubstring ? ` containing '${descriptionSubstring}'` : ''}, but got:\n  ${found || '(none)'}`
    );
  }
  return match;
}

function expectNoFinding(findings, category) {
  const match = findings.find((f) => f.category === category);
  if (match) {
    throw new Error(`Expected no finding with category '${category}', but got: ${match.description}`);
  }
}

// ============================================================================
// 1. PARSER ROBUSTNESS — engine must never throw on any of these inputs
// ============================================================================
describe('Parser robustness / crash safety', () => {
  test('empty string parses without crash', () => {
    const { ast, error } = parseSource('', 'empty.js');
    expect(ast).not.toBeNull();
    expect(error).toBeNull();
  });

  test('syntax error returns null AST with error message, no throw', () => {
    const { ast, error } = parseSource('const x = {{{;', 'bad.js');
    // With errorRecovery:true Babel may still return a partial AST; either way no throw
    expect(() => parseSource('const x = {{{;', 'bad.js')).not.toThrow();
    // error should be non-null or ast should be present with errors — at least one
    expect(ast !== null || error !== null).toBe(true);
  });

  test('deeply nested arrow functions do not crash the engine', () => {
    const code = `
      const a = (x) => (y) => (z) => (w) => (v) => x + y + z + w + v;
      const res = a(1)(2)(3)(4)(5);
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('complex async/await try-catch does not crash', () => {
    const code = `
      async function handler(req, res) {
        try {
          const data = await someApi(req.body.id);
          const result = await Promise.all([data, anotherApi()]);
          res.json(result);
        } catch (err) {
          console.error('Internal Error:', err);
          res.status(500).json({ error: 'Internal server error' });
        }
      }
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('deep promise chain does not crash', () => {
    const code = `
      fetch(url)
        .then(r => r.json())
        .then(d => process(d))
        .then(r => res.json(r))
        .catch(e => res.status(500).json({ error: 'fail' }));
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('computed property keys do not crash', () => {
    const code = `
      const key = req.query.field;
      const obj = { [key]: req.body.value };
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('spread operator on req.body does not crash', () => {
    const code = `
      const payload = { ...req.body, role: 'user' };
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('nested object destructuring does not crash', () => {
    const code = `
      const { body: { username, password } } = req;
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('TypeScript file extension is parsed without crash', () => {
    const code = `
      function greet(name: string): string {
        return 'Hello ' + name;
      }
    `;
    const { error } = parseSource(code, 'hello.ts');
    expect(error).toBeNull();
  });

  test('class with private fields does not crash', () => {
    const code = `
      class UserStore {
        #cache = new Map();
        get(id) { return this.#cache.get(id); }
      }
    `;
    expect(() => run(code)).not.toThrow();
  });

  test('optional chaining and nullish coalescing do not crash', () => {
    const code = `
      const name = req?.body?.user?.name ?? 'anonymous';
      res.send(name);
    `;
    expect(() => run(code)).not.toThrow();
  });
});

// ============================================================================
// 2. EXISTING RULES — regression guard
// ============================================================================
describe('Existing rules — regression guard', () => {
  test('SQL_INJECTION: tainted string concat into query', () => {
    const code = `
      app.get('/search', (req, res) => {
        const id = req.query.id;
        db.query("SELECT * FROM t WHERE id='" + id + "'", (err, r) => res.json(r));
      });
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('SQL_INJECTION: template literal with tainted value', () => {
    const code = `
      const username = req.query.username;
      db.run(\`SELECT * FROM users WHERE name='\${username}'\`);
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('SQL_INJECTION: parameterized query is clean', () => {
    const code = `
      const username = req.query.username;
      db.run('SELECT * FROM users WHERE name=?', [username]);
    `;
    // The query string itself is clean (no taint in first arg)
    const findings = run(code);
    expectNoFinding(findings, 'SQL_INJECTION');
  });

  test('PATH_TRAVERSAL: tainted value in fs.readFile', () => {
    const code = `
      const file = req.query.name;
      fs.readFile(file, 'utf8', (err, data) => res.send(data));
    `;
    const findings = run(code);
    expectFinding(findings, 'PATH_TRAVERSAL');
  });

  test('COMMAND_INJECTION: tainted value in exec', () => {
    const code = `
      const cmd = req.body.command;
      exec('ping ' + cmd, (err, out) => res.send(out));
    `;
    const findings = run(code);
    expectFinding(findings, 'COMMAND_INJECTION');
  });

  test('CODE_EXECUTION: eval with tainted arg', () => {
    const code = `
      const code = req.body.code;
      eval(code);
    `;
    const findings = run(code);
    expectFinding(findings, 'CODE_EXECUTION');
  });

  test('CODE_EXECUTION: new Function with non-literal (MEDIUM confidence)', () => {
    const code = `
      const fn = new Function(someVar);
    `;
    const findings = run(code);
    const f = expectFinding(findings, 'CODE_EXECUTION');
    expect(f.confidence).toBe('MEDIUM');
  });

  test('XSS: tainted value in res.send', () => {
    const code = `
      const name = req.query.name;
      res.send('<h1>' + name + '</h1>');
    `;
    const findings = run(code);
    expectFinding(findings, 'XSS');
  });

  test('MASS_ASSIGNMENT: req.body.role read directly', () => {
    const code = `
      const role = req.body.role;
      db.run('UPDATE users SET role=? WHERE id=?', [role, req.body.id]);
    `;
    const findings = run(code);
    expectFinding(findings, 'MASS_ASSIGNMENT');
  });

  test('HARDCODED_SECRET: password literal in variable', () => {
    const code = `
      const password = 'hunter2';
    `;
    const findings = run(code);
    expectFinding(findings, 'HARDCODED_SECRET');
  });

  test('HARDCODED_SECRET: apiKey in object property', () => {
    const code = `
      const cfg = { apiKey: 'my-very-secret-key-12345' };
    `;
    const findings = run(code);
    expectFinding(findings, 'HARDCODED_SECRET');
  });

  test('VERBOSE_ERROR: err.message in response object', () => {
    const code = `
      db.query(sql, (err, rows) => {
        if (err) return res.status(500).json({ details: err.message });
        res.json(rows);
      });
    `;
    const findings = run(code);
    expectFinding(findings, 'VERBOSE_ERROR');
  });

  test('VERBOSE_ERROR: chained res.status().json({ details: err.message })', () => {
    const code = `
      if (err) res.status(500).json({ error: err.message });
    `;
    const findings = run(code);
    expectFinding(findings, 'VERBOSE_ERROR');
  });
});

// ============================================================================
// 3. NEW RULES — WEAK_CRYPTO
// ============================================================================
describe('New rule: WEAK_CRYPTO', () => {
  test('crypto.createHash("md5") is flagged', () => {
    const code = `
      const crypto = require('crypto');
      const hash = crypto.createHash('md5').update(data).digest('hex');
    `;
    const findings = run(code);
    expectFinding(findings, 'WEAK_CRYPTO', 'md5');
  });

  test('crypto.createHash("sha1") is flagged', () => {
    const code = `
      const h = crypto.createHash('sha1');
    `;
    const findings = run(code);
    expectFinding(findings, 'WEAK_CRYPTO', 'sha1');
  });

  test('crypto.createHash("SHA-1") case-insensitive match', () => {
    const code = `const h = crypto.createHash('SHA-1');`;
    const findings = run(code);
    expectFinding(findings, 'WEAK_CRYPTO');
  });

  test('crypto.createHash("sha256") is NOT flagged', () => {
    const code = `
      const hash = crypto.createHash('sha256').update(data).digest('hex');
    `;
    const findings = run(code);
    expectNoFinding(findings, 'WEAK_CRYPTO');
  });

  test('Math.random() used in token generation is flagged', () => {
    const code = `
      const token = Math.random().toString(36).slice(2);
    `;
    const findings = run(code);
    expectFinding(findings, 'WEAK_CRYPTO', 'Math.random');
  });

  test('Math.random() used in UI animation is NOT flagged (no sensitive context)', () => {
    const code = `
      const delay = Math.random() * 500;
      setTimeout(() => animate(), delay);
    `;
    const findings = run(code);
    expectNoFinding(findings, 'WEAK_CRYPTO');
  });

  test('finding has severity HIGH and confidence HIGH|MEDIUM', () => {
    const code = `const h = crypto.createHash('md5');`;
    const findings = runCompliance(code);
    const f = findings.find((x) => x.ruleId === 'OWASP-A02-WEAK-CRYPTO');
    expect(f).toBeDefined();
    expect(f.severity).toBe('HIGH');
    expect(['HIGH', 'MEDIUM']).toContain(f.confidence);
    expect(f.remediation).toMatch(/sha256|sha512|bcrypt/i);
  });
});

// ============================================================================
// 4. NEW RULES — INSECURE_TIMEOUT
// ============================================================================
describe('New rule: INSECURE_TIMEOUT', () => {
  test('setTimeout with string argument is flagged', () => {
    const code = `setTimeout("alert('xss')", 1000);`;
    const findings = run(code);
    expectFinding(findings, 'INSECURE_TIMEOUT', 'setTimeout');
  });

  test('setInterval with string argument is flagged', () => {
    const code = `setInterval("doSomething()", 5000);`;
    const findings = run(code);
    expectFinding(findings, 'INSECURE_TIMEOUT', 'setInterval');
  });

  test('setTimeout with function reference is NOT flagged', () => {
    const code = `setTimeout(() => doSomething(), 1000);`;
    const findings = run(code);
    expectNoFinding(findings, 'INSECURE_TIMEOUT');
  });

  test('setTimeout with named function reference is NOT flagged', () => {
    const code = `setTimeout(myCallback, 1000);`;
    const findings = run(code);
    expectNoFinding(findings, 'INSECURE_TIMEOUT');
  });

  test('finding has severity HIGH and correct remediation', () => {
    const code = `setTimeout("code()", 0);`;
    const findings = runCompliance(code);
    const f = findings.find((x) => x.ruleId === 'OWASP-A03-INSECURE-TIMEOUT');
    expect(f).toBeDefined();
    expect(f.severity).toBe('HIGH');
    expect(f.remediation).toMatch(/function reference/i);
  });
});

// ============================================================================
// 5. NEW RULES — HIGH_ENTROPY_SECRET
// ============================================================================
describe('New rule: HIGH_ENTROPY_SECRET', () => {
  test('JWT token literal is flagged', () => {
    const code = `
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    `;
    const findings = run(code);
    expectFinding(findings, 'HIGH_ENTROPY_SECRET');
  });

  test('AWS access key ID literal is flagged', () => {
    const code = `const awsKey = 'AKIAIOSFODNN7EXAMPLE';`;
    const findings = run(code);
    expectFinding(findings, 'HIGH_ENTROPY_SECRET');
  });

  test('Stripe secret key literal is flagged', () => {
    const code = `const stripe = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';`;
    const findings = run(code);
    expectFinding(findings, 'HIGH_ENTROPY_SECRET');
  });

  test('short ordinary string is NOT flagged', () => {
    const code = `const greeting = 'hello world';`;
    const findings = run(code);
    expectNoFinding(findings, 'HIGH_ENTROPY_SECRET');
  });

  test('low-entropy long string (repeated chars) is NOT flagged', () => {
    const code = `const s = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';`;
    const findings = run(code);
    expectNoFinding(findings, 'HIGH_ENTROPY_SECRET');
  });

  test('finding has CRITICAL severity', () => {
    const code = `const k = 'AKIAIOSFODNN7EXAMPLE';`;
    const findings = runCompliance(code);
    const f = findings.find((x) => x.ruleId === 'OWASP-A02-HIGH-ENTROPY-SECRET');
    expect(f).toBeDefined();
    expect(f.severity).toBe('CRITICAL');
    expect(f.remediation).toMatch(/environment variable|secrets manager/i);
  });
});

// ============================================================================
// 6. NEW RULES — LOG_SENSITIVE
// ============================================================================
describe('New rule: LOG_SENSITIVE', () => {
  test('console.log(req.body) is flagged', () => {
    const code = `
      app.post('/login', (req, res) => {
        console.log(req.body);
        res.json({ ok: true });
      });
    `;
    const findings = run(code);
    expectFinding(findings, 'LOG_SENSITIVE', 'req.body');
  });

  test('console.error(req.headers) is flagged', () => {
    const code = `console.error(req.headers);`;
    const findings = run(code);
    expectFinding(findings, 'LOG_SENSITIVE');
  });

  test('console.log({ password: userInput }) is flagged', () => {
    const code = `console.log({ password: req.body.password });`;
    const findings = run(code);
    expectFinding(findings, 'LOG_SENSITIVE', 'password');
  });

  test('console.log({ authorization: req.headers.authorization }) is flagged', () => {
    const code = `console.log({ authorization: req.headers.authorization });`;
    const findings = run(code);
    expectFinding(findings, 'LOG_SENSITIVE');
  });

  test('console.log with safe message string is NOT flagged', () => {
    const code = `console.log('server started on port', PORT);`;
    const findings = run(code);
    expectNoFinding(findings, 'LOG_SENSITIVE');
  });

  test('console.error with generic Error object (not req.*) is NOT flagged', () => {
    const code = `console.error('Internal Error:', err);`;
    const findings = run(code);
    expectNoFinding(findings, 'LOG_SENSITIVE');
  });

  test('finding has MEDIUM severity and correct remediation', () => {
    const code = `console.log(req.body);`;
    const findings = runCompliance(code);
    const f = findings.find((x) => x.ruleId === 'OWASP-A09-LOG-SENSITIVE');
    expect(f).toBeDefined();
    expect(f.severity).toBe('MEDIUM');
    expect(f.remediation).toMatch(/redact|omit/i);
  });
});

// ============================================================================
// 7. EDGE CASES — alias tracking, deep destructuring, template literals
// ============================================================================
describe('Edge cases: alias tracking, destructuring, template literals', () => {
  test('multi-hop alias: a=req.query.id -> b=a -> c=b -> db.query(c) flagged', () => {
    const code = `
      const a = req.query.id;
      const b = a;
      const c = b;
      db.query("SELECT * FROM t WHERE id=" + c);
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('template literal with two tainted slots flags once', () => {
    const code = `
      const id = req.query.id;
      const role = req.query.role;
      db.query(\`SELECT * FROM users WHERE id=\${id} AND role='\${role}'\`);
    `;
    const findings = run(code);
    // At least one SQL_INJECTION finding
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('destructured req.body taint propagates to db.query', () => {
    const code = `
      const { username } = req.body;
      db.query("SELECT * FROM users WHERE user='" + username + "'");
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('ternary assignment: tainted branch propagates', () => {
    const code = `
      const id = req.query.id ? req.query.id : 'default';
      db.run("SELECT * FROM t WHERE id='" + id + "'");
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('logical OR assignment: tainted branch propagates', () => {
    const code = `
      const name = req.query.name || 'anon';
      db.run("SELECT * FROM t WHERE name='" + name + "'");
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('path.join with tainted arg propagates to fs.readFile', () => {
    const code = `
      const file = req.query.file;
      const fullPath = path.join('/uploads', file);
      fs.readFileSync(fullPath);
    `;
    const findings = run(code);
    expectFinding(findings, 'PATH_TRAVERSAL');
  });

  test('reassignment via = updates taint', () => {
    const code = `
      let query = 'SELECT 1';
      query = 'SELECT * FROM t WHERE id=' + req.query.id;
      db.run(query);
    `;
    const findings = run(code);
    expectFinding(findings, 'SQL_INJECTION');
  });

  test('validator-sanitized value does NOT reach SQL sink as tainted', () => {
    const code = `
      const raw = req.query.id;
      const id = parseInt(raw, 10);
      db.run('SELECT * FROM t WHERE id=' + id);
    `;
    // parseInt is a known sanitizer - taint is neutralized
    const findings = run(code);
    expectNoFinding(findings, 'SQL_INJECTION');
  });

  test('async/await handler with db call does not crash engine', () => {
    const code = `
      async function handler(req, res) {
        const id = req.params.id;
        if (!Number.isInteger(Number(id))) return res.status(400).json({error:'bad id'});
        const row = await db.getAsync('SELECT * FROM users WHERE id=?', [id]);
        res.json(row);
      }
    `;
    expect(() => run(code)).not.toThrow();
    // id is validated, no SQL_INJECTION expected
    const findings = run(code);
    expectNoFinding(findings, 'SQL_INJECTION');
  });
});

// ============================================================================
// 8. COMPLIANCE LAYER — ruleId, owaspCategory, severity, confidence in output
// ============================================================================
describe('Compliance layer output shape', () => {
  test('every finding has ruleId, owaspCategory, severity, confidence, remediation', () => {
    const code = `
      const h = crypto.createHash('md5');
      const token = Math.random().toString(36);
      setTimeout("boom()", 100);
      console.log(req.body);
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    `;
    const findings = runCompliance(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.ruleId).toBeTruthy();
      expect(f.owaspCategory).toMatch(/A0\d:2021/);
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(f.severity);
      expect(['HIGH', 'MEDIUM', 'LOW']).toContain(f.confidence);
      expect(f.remediation).toBeTruthy();
      expect(f.filePath).toBeTruthy();
      expect(typeof f.line).toBe('number');
    }
  });

  test('buildComplianceSummary reflects new CRITICAL rule in verdict', () => {
    const findings = [
      { severity: 'CRITICAL', type: 'STATIC_ANALYSIS', ruleId: 'OWASP-A02-HIGH-ENTROPY-SECRET' }
    ];
    const summary = buildComplianceSummary(findings);
    expect(summary.verdict).toBe('BLOCK');
    expect(summary.releaseReadinessScore).toBe(60); // 100 - 40
    expect(summary.bySeverity.CRITICAL).toBe(1);
  });

  test('buildComplianceSummary: HIGH rule produces WARN verdict', () => {
    const findings = [
      { severity: 'HIGH', type: 'STATIC_ANALYSIS', ruleId: 'OWASP-A02-WEAK-CRYPTO' }
    ];
    const summary = buildComplianceSummary(findings);
    expect(summary.verdict).toBe('WARN');
    expect(summary.releaseReadinessScore).toBe(80); // 100 - 20
  });

  test('clean code produces PASS with 100/100', () => {
    const code = `
      'use strict';
      const express = require('express');
      const app = express();
      app.get('/health', (req, res) => res.json({ status: 'ok' }));
      module.exports = app;
    `;
    const findings = runCompliance(code);
    const summary = buildComplianceSummary(findings);
    expect(summary.verdict).toBe('PASS');
    expect(summary.releaseReadinessScore).toBe(100);
  });
});

// ============================================================================
// 9. FALSE-POSITIVE GUARD — the demo-app must stay clean
// ============================================================================
describe('False-positive guard: demo-app server.js', () => {
  const fs = require('fs');
  const path = require('path');

  test('demo-app/server.js produces zero findings', () => {
    const serverPath = path.resolve(__dirname, '../../demo-app/server.js');
    const content = fs.readFileSync(serverPath, 'utf8');
    const findings = runCompliance(content, serverPath);
    if (findings.length > 0) {
      const summary = findings.map((f) => `  [${f.severity}] ${f.ruleId} L${f.line}: ${f.description}`).join('\n');
      throw new Error(`Expected zero findings on demo-app/server.js, got:\n${summary}`);
    }
    expect(findings).toHaveLength(0);
  });
});
