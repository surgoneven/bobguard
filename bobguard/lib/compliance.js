'use strict';

/**
 * Rule evaluation & compliance summary using the AST taint engine.
 * Falls back to regex scanning per-file on parse failure.
 */

const fs = require('fs');
const path = require('path');

const { parseSource } = require('./parser');
const { analyzeFile } = require('./taintEngine');
const { loadIgnorePatterns, listScannableFiles, createLimiter } = require('./scanUtils');

/** Rule metadata table (read by sarif.js for SARIF rule descriptors). */
const RULES = [
  {
    id: 'TAINT-SQL-INJECTION',
    owaspCategory: 'A03:2021 - Injection',
    severity: 'CRITICAL',
    description: 'Tainted (user-controlled) data flows into a SQL query without parameterization.',
    remediation: 'Use parameterized queries (? placeholders) and pass tainted values via the params array, never by building the SQL string with them.'
  },
  {
    id: 'TAINT-COMMAND-INJECTION',
    owaspCategory: 'A03:2021 - Injection',
    severity: 'CRITICAL',
    description: 'Tainted data flows into a shell command execution call (exec/spawn/execFile).',
    remediation: 'Avoid building shell commands from user input; use a fixed command allow-list or a non-shell API.'
  },
  {
    id: 'TAINT-CODE-EXECUTION',
    owaspCategory: 'A03:2021 - Injection',
    severity: 'HIGH',
    description: "Dynamic code execution ('eval' / 'new Function') called with a non-literal argument.",
    remediation: 'Remove dynamic code execution entirely; use explicit parsing or a dispatch table instead.'
  },
  {
    id: 'TAINT-PATH-TRAVERSAL',
    owaspCategory: 'A01:2021 - Broken Access Control',
    severity: 'HIGH',
    description: 'Tainted data used to build a filesystem path passed to an fs.* call.',
    remediation: 'Resolve against a fixed base directory and reject any path that escapes it before touching the filesystem.'
  },
  {
    id: 'TAINT-XSS',
    owaspCategory: 'A03:2021 - Injection',
    severity: 'MEDIUM',
    description: 'Tainted data written directly to the HTTP response body without escaping.',
    remediation: 'HTML-encode output for HTML contexts, or use res.json() for structured data instead of building HTML/text manually.'
  },
  {
    id: 'OWASP-A08-MASS-ASSIGNMENT',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    severity: 'HIGH',
    description: 'A privileged field (role/isAdmin/...) is read directly from request input.',
    remediation: 'Never trust a client-supplied privilege field; assign it server-side only, from an authenticated/authorized source.'
  },
  {
    id: 'OWASP-A04-UNVALIDATED-INPUT',
    owaspCategory: 'A04:2021 - Insecure Design',
    severity: 'MEDIUM',
    description: 'Request input is used with no validation guard (comparison, typeof check, or validator call) found before use.',
    remediation: 'Add an explicit type/format/presence check before using external input.'
  },
  {
    id: 'OWASP-A02-HARDCODED-SECRET',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    severity: 'HIGH',
    description: 'Possible hardcoded credential or secret literal in source.',
    remediation: 'Move secrets to environment variables or a secrets manager; never commit literal credentials to source.'
  },
  {
    id: 'OWASP-A09-VERBOSE-ERROR',
    owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
    severity: 'LOW',
    description: 'Raw error/exception details returned directly in the HTTP response, risking information disclosure.',
    remediation: 'Log full error details server-side only; return a generic error message to the client.'
  },
  {
    id: 'OWASP-A02-WEAK-CRYPTO',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    severity: 'HIGH',
    description: 'Weak or broken cryptographic algorithm (MD5, SHA-1) or insecure randomness (Math.random()) used in a security-sensitive context.',
    remediation: "Use SHA-256/SHA-512 for general hashing, bcrypt/argon2 for passwords, and crypto.randomBytes()/crypto.randomUUID() for token generation."
  },
  {
    id: 'OWASP-A03-INSECURE-TIMEOUT',
    owaspCategory: 'A03:2021 - Injection',
    severity: 'HIGH',
    description: "setTimeout() or setInterval() called with a string argument, causing implicit eval().",
    remediation: 'Pass a function reference instead of a string to setTimeout/setInterval.'
  },
  {
    id: 'OWASP-A02-HIGH-ENTROPY-SECRET',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    severity: 'CRITICAL',
    description: 'High-entropy string literal detected that matches a known secret pattern (JWT, AWS key, Stripe key, or base64 blob).',
    remediation: 'Remove hardcoded secrets; load them from environment variables or a secrets manager at runtime.'
  },
  {
    id: 'OWASP-A09-LOG-SENSITIVE',
    owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
    severity: 'MEDIUM',
    description: 'Sensitive data (request body, password, authorization header, or token) is passed directly to a console log call.',
    remediation: 'Redact or omit sensitive fields before logging; never log raw request bodies or authorization headers.'
  }
];

const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

/** Maps a taintEngine finding category to its RULES entry id. */
const CATEGORY_TO_RULE_ID = {
  SQL_INJECTION: 'TAINT-SQL-INJECTION',
  COMMAND_INJECTION: 'TAINT-COMMAND-INJECTION',
  CODE_EXECUTION: 'TAINT-CODE-EXECUTION',
  PATH_TRAVERSAL: 'TAINT-PATH-TRAVERSAL',
  XSS: 'TAINT-XSS',
  MASS_ASSIGNMENT: 'OWASP-A08-MASS-ASSIGNMENT',
  UNVALIDATED_INPUT: 'OWASP-A04-UNVALIDATED-INPUT',
  HARDCODED_SECRET: 'OWASP-A02-HARDCODED-SECRET',
  VERBOSE_ERROR: 'OWASP-A09-VERBOSE-ERROR',
  WEAK_CRYPTO: 'OWASP-A02-WEAK-CRYPTO',
  INSECURE_TIMEOUT: 'OWASP-A03-INSECURE-TIMEOUT',
  HIGH_ENTROPY_SECRET: 'OWASP-A02-HIGH-ENTROPY-SECRET',
  LOG_SENSITIVE: 'OWASP-A09-LOG-SENSITIVE'
};

/** Confidence -> severity override (applies only to CODE_EXECUTION). */
const CONFIDENCE_SEVERITY_OVERRIDE = {
  CODE_EXECUTION: { HIGH: 'CRITICAL', MEDIUM: 'HIGH' }
};

/**
 * Converts a taintEngine finding to the STATIC_ANALYSIS finding shape.
 * @param {object} taintFinding
 * @returns {object}
 */
function toPublicFinding(taintFinding) {
  const ruleId = CATEGORY_TO_RULE_ID[taintFinding.category];
  const rule = RULES_BY_ID.get(ruleId);
  const override = CONFIDENCE_SEVERITY_OVERRIDE[taintFinding.category];
  const severity = (override && override[taintFinding.confidence]) || (rule ? rule.severity : 'MEDIUM');

  return {
    type: 'STATIC_ANALYSIS',
    ruleId,
    owaspCategory: rule ? rule.owaspCategory : 'Unclassified',
    severity,
    description: taintFinding.description,
    remediation: taintFinding.remediation,
    filePath: taintFinding.filePath,
    line: taintFinding.line,
    snippet: taintFinding.snippet,
    // Additive fields - present for callers that want them (a future
    // sarif.js enrichment, a richer CLI printout), safely ignored by
    // existing callers that only read the fields above.
    confidence: taintFinding.confidence,
    taintPath: taintFinding.taintPath,
    tags: taintFinding.tags
  };
}

// --- Legacy regex fallback (used ONLY when a file fails to parse) --------

const LEGACY_REGEX_RULES = [
  {
    id: 'TAINT-SQL-INJECTION',
    pattern: /(SELECT|INSERT|UPDATE|DELETE)[\s\S]*?['"]\s*\+\s*\w+|['"]\s*\+\s*\w+[\s\S]*?(SELECT|INSERT|UPDATE|DELETE)|`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}[^`]*`/i
  },
  {
    id: 'OWASP-A08-MASS-ASSIGNMENT',
    pattern: /req\.body\.(role|isAdmin|is_admin|admin|permissions)\b/
  },
  {
    id: 'OWASP-A04-UNVALIDATED-INPUT',
    pattern: /const\s+\w+\s*=\s*req\.(body|query|params)(?!\s*\.\s*\w+\s*&&)/
  },
  {
    id: 'OWASP-A02-HARDCODED-SECRET',
    pattern: /(password|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{4,}['"]/i
  },
  {
    id: 'OWASP-A09-VERBOSE-ERROR',
    pattern: /res\.\w+\([^)]*\berr(?:or)?\.message\b/
  }
];

/**
 * Regex fallback scan for a single file when AST parsing fails.
 * @param {{filePath: string, lines: string[]}} file
 * @returns {object[]}
 */
function runLegacyRegexScan(file) {
  const findings = [];
  file.lines.forEach((lineText, index) => {
    LEGACY_REGEX_RULES.forEach((legacyRule) => {
      if (legacyRule.pattern.test(lineText)) {
        const rule = RULES_BY_ID.get(legacyRule.id);
        findings.push({
          type: 'STATIC_ANALYSIS',
          ruleId: legacyRule.id,
          owaspCategory: rule.owaspCategory,
          severity: rule.severity,
          description: `${rule.description} (regex fallback - file could not be parsed as valid JS/TS)`,
          remediation: rule.remediation,
          filePath: file.filePath,
          line: index + 1,
          snippet: lineText.trim().slice(0, 160),
          confidence: 'LOW',
          taintPath: null,
          tags: {}
        });
      }
    });
  });
  return findings;
}

/**
 * Evaluates OWASP rules against pre-loaded source files.
 * Uses AST/taint analysis; falls back to regex per-file on parse failure.
 * @param {Array<{filePath: string, content: string, lines: string[]}>} sourceFiles
 * @returns {object[]}
 */
function evaluateOwaspRules(sourceFiles) {
  const findings = [];

  sourceFiles.forEach((file) => {
    const { ast, error } = parseSource(file.content, file.filePath);

    if (!ast) {
      // Parse failed - fall back to regex for this file only. Never throw;
      // a syntax error in one file should not stop the audit.
      findings.push(...runLegacyRegexScan(file));
      return;
    }

    let taintFindings;
    try {
      taintFindings = analyzeFile(ast, file.filePath, file.lines);
    } catch (engineErr) {
      // Defensive: an unexpected AST shape should degrade to the regex
      // fallback for this file, not crash the whole audit.
      findings.push(...runLegacyRegexScan(file));
      return;
    }

    findings.push(...taintFindings.map(toPublicFinding));
  });

  return findings;
}

/**
 * Streaming entrypoint for large repos: walks targetDir with bounded
 * concurrency, processing one file at a time to keep memory use flat.
 * @param {string} targetDir
 * @param {{concurrency?: number}} [options]
 * @returns {Promise<object[]>}
 */
async function evaluateOwaspRulesFromDirectory(targetDir, options = {}) {
  const concurrency = options.concurrency || 8;
  const resolvedRoot = path.resolve(targetDir);
  const patterns = loadIgnorePatterns(resolvedRoot);
  const files = listScannableFiles(resolvedRoot, patterns);
  const limit = createLimiter(concurrency);

  const perFileResults = await Promise.all(
    files.map((filePath) =>
      limit(async () => {
        let content;
        try {
          content = fs.readFileSync(filePath, 'utf8');
        } catch (readErr) {
          return [];
        }

        const lines = content.split(/\r?\n/);
        const { ast } = parseSource(content, filePath);

        let result;
        if (!ast) {
          result = runLegacyRegexScan({ filePath, lines });
        } else {
          try {
            result = analyzeFile(ast, filePath, lines).map(toPublicFinding);
          } catch (engineErr) {
            result = runLegacyRegexScan({ filePath, lines });
          }
        }

        // Content and AST fall out of scope here and become GC-eligible
        // immediately - nothing holds a reference past this task.
        return result;
      })
    )
  );

  return perFileResults.flat();
}

const SEVERITY_WEIGHT = { CRITICAL: 40, HIGH: 20, MEDIUM: 10, LOW: 5 };
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * Builds a compliance summary with 0-100 release readiness score.
 * @param {Array<object>} findings
 * @returns {object}
 */
function buildComplianceSummary(findings) {
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  findings.forEach((f) => {
    if (bySeverity.hasOwnProperty(f.severity)) {
      bySeverity[f.severity] += 1;
    }
  });

  const totalDeduction = SEVERITY_ORDER.reduce(
    (sum, sev) => sum + bySeverity[sev] * SEVERITY_WEIGHT[sev],
    0
  );
  const releaseReadinessScore = Math.max(0, 100 - totalDeduction);

  let verdict = 'PASS';
  if (bySeverity.CRITICAL > 0) {
    verdict = 'BLOCK';
  } else if (bySeverity.HIGH > 0) {
    verdict = 'WARN';
  }

  return {
    totalFindings: findings.length,
    bySeverity,
    releaseReadinessScore,
    verdict,
    generatedAt: new Date().toISOString()
  };
}

module.exports = {
  RULES,
  evaluateOwaspRules,
  evaluateOwaspRulesFromDirectory,
  buildComplianceSummary
};