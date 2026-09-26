'use strict';

/**
 * Lightweight, scope-aware taint analysis engine.
 *
 * Scope: this is deliberately NOT a full production dataflow solver. It is
 * a single top-to-bottom traversal per file that:
 *   1. Pre-scans local function/arrow declarations to build a tiny
 *      "taint transfer summary" for each (passthrough / sanitizes / unknown),
 *      giving basic inter-procedural coverage for same-file helper functions
 *      (this is exactly what lets it correctly recognize validator helpers
 *      like `function isValidId(id) { return /^[0-9]+$/.test(id); }` as
 *      sanitizers instead of re-flagging their callers).
 *   2. Walks the AST once, marking variable bindings as tainted when their
 *      initializer traces back to an HTTP input or environment source, and
 *      checking call expressions against a sink table as it goes.
 *
 * Traversal is source-order dependent (a binding must be visited before a
 * later sink that reads it, which holds for typical straight-line Express
 * handler code but is not a guarantee for out-of-order/hoisted patterns).
 * That trade-off is intentional: it keeps the engine O(nodes) per file with
 * no fixed-point iteration, which is what "lightweight" means here.
 */

const traverse = require('@babel/traverse').default;

// --- Sanitizer / neutralizing function names ---------------------------

const SANITIZER_CALL_NAMES = new Set([
  'parseInt',
  'parseFloat',
  'Number',
  'encodeURIComponent',
  'encodeURI',
  'escape'
]);

// object.method() sanitizer pairs, e.g. validator.escape(x), DOMPurify.sanitize(x)
const SANITIZER_MEMBER_CALLS = [
  { object: 'validator', properties: ['escape', 'isEmail', 'isAlphanumeric', 'isURL', 'isUUID', 'whitelist', 'blacklist'] },
  { object: 'DOMPurify', properties: ['sanitize'] },
  { object: 'sanitizeHtml', properties: [] }, // called directly, handled separately
  { object: 'validatorPkg', properties: ['escape'] }
];

const BOOLEAN_PRODUCING_MEMBER_METHODS = new Set(['test', 'includes', 'startsWith', 'endsWith']);

// --- Sink tables ---------------------------------------------------------

const SQL_SINK_METHODS = new Set(['query', 'run', 'all', 'get', 'execute', 'exec']);
const FS_SINK_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'unlink', 'unlinkSync', 'appendFile', 'appendFileSync',
  'createReadStream', 'createWriteStream', 'open', 'openSync'
]);
const CMD_SINK_NAMES = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']);
const XSS_SINK_METHODS = new Set(['send', 'write']);

const COMPLIANCE_TAGS = {
  SQL_INJECTION: { owasp: 'A03:2021-Injection', cwe: 'CWE-89', soc2: 'CC6.1' },
  COMMAND_INJECTION: { owasp: 'A03:2021-Injection', cwe: 'CWE-78', soc2: 'CC6.1' },
  CODE_EXECUTION: { owasp: 'A03:2021-Injection', cwe: 'CWE-95', soc2: 'CC6.1' },
  PATH_TRAVERSAL: { owasp: 'A01:2021-Broken Access Control', cwe: 'CWE-22', soc2: 'CC6.1' },
  XSS: { owasp: 'A03:2021-Injection', cwe: 'CWE-79', soc2: 'CC6.6' },
  MASS_ASSIGNMENT: { owasp: 'A08:2021-Software and Data Integrity Failures', cwe: 'CWE-915', soc2: 'CC6.1' },
  UNVALIDATED_INPUT: { owasp: 'A04:2021-Insecure Design', cwe: 'CWE-20', soc2: 'CC6.1' },
  HARDCODED_SECRET: { owasp: 'A02:2021-Cryptographic Failures', cwe: 'CWE-798', soc2: 'CC6.1', pciDss: 'PCI-DSS:3.4' },
  VERBOSE_ERROR: { owasp: 'A09:2021-Security Logging and Monitoring Failures', cwe: 'CWE-209', soc2: 'CC7.2' },
  WEAK_CRYPTO: { owasp: 'A02:2021-Cryptographic Failures', cwe: 'CWE-327', soc2: 'CC6.1' },
  INSECURE_TIMEOUT: { owasp: 'A03:2021-Injection', cwe: 'CWE-95', soc2: 'CC6.1' },
  HIGH_ENTROPY_SECRET: { owasp: 'A02:2021-Cryptographic Failures', cwe: 'CWE-798', soc2: 'CC6.1', pciDss: 'PCI-DSS:3.4' },
  LOG_SENSITIVE: { owasp: 'A09:2021-Security Logging and Monitoring Failures', cwe: 'CWE-532', soc2: 'CC7.2' }
};

const MASS_ASSIGNMENT_PROPS = new Set([
  'role', 'isadmin', 'is_admin', 'admin', 'permissions', 'scope', 'issuperuser', 'superuser'
]);

const SECRET_KEY_PATTERN = /password|secret|api[_-]?key|token/i;

// --- New rule constants --------------------------------------------------

// Weak hashing algorithms flagged by OWASP-A02.
const WEAK_HASH_ALGORITHMS = new Set(['md5', 'sha1', 'sha-1', 'md4', 'md2']);

// Log methods whose argument list might expose sensitive data.
const LOG_METHODS = new Set(['log', 'error', 'warn', 'info', 'debug', 'trace']);

// Sensitive field names that must never be logged.
const SENSITIVE_LOG_FIELDS = new Set([
  'password', 'passwd', 'secret', 'authorization', 'auth', 'token', 'apikey', 'api_key',
  'creditcard', 'credit_card', 'ssn', 'cvv'
]);

/**
 * Returns the Shannon entropy (bits per character) of a string.
 * Values >= 4.0 on strings ≥ 16 chars are considered high-entropy.
 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((h, c) => {
    const p = c / str.length;
    return h - p * Math.log2(p);
  }, 0);
}

/**
 * Returns true when a string literal looks like a hardcoded high-entropy secret
 * (JWT, AWS key, Stripe key, or high-entropy base64 blob ≥ 16 chars).
 */
function isHighEntropySecret(value) {
  if (typeof value !== 'string' || value.length < 16) return false;
  // JWT: three base64url-encoded segments separated by dots
  if (/^eyJ[A-Za-z0-9+/_-]{8,}\.[A-Za-z0-9+/_-]{4,}\.[A-Za-z0-9+/_=-]{4,}$/.test(value)) return true;
  // Stripe keys
  if (/^(sk_live_|sk_test_|rk_live_)[A-Za-z0-9]{10,}$/.test(value)) return true;
  // AWS access key ID
  if (/^AKIA[0-9A-Z]{16}$/.test(value)) return true;
  // Generic: long base64-ish blob with high entropy
  if (value.length >= 32 && /^[A-Za-z0-9+/=]{32,}$/.test(value) && shannonEntropy(value) >= 4.5) return true;
  return false;
}

/**
 * Checks whether a call-expression node is (transitively) a call on `res`,
 * so chained calls like res.status(500).json({...}) are recognized as one
 * response-sending chain rather than missed because the outer call's
 * callee.object is itself a CallExpression, not the `res` identifier.
 */
function rootsAtResIdentifier(node) {
  if (!node) return false;
  if (node.type === 'Identifier') return node.name === 'res';
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    return rootsAtResIdentifier(node.callee.object);
  }
  if (node.type === 'MemberExpression') {
    return rootsAtResIdentifier(node.object);
  }
  return false;
}

/**
 * Determines whether a reference to a raw-source-derived identifier sits in
 * a validating position (a comparison, a boolean guard, an if/ternary test,
 * or an argument to a boolean-producing validator method). Walks a bounded
 * number of parent levels rather than doing full control-flow analysis -
 * enough to recognize the common guard idioms, not a soundness guarantee.
 */
function isValidationUsage(refPath) {
  let cur = refPath;
  for (let i = 0; i < 6 && cur; i++) {
    const parent = cur.parentPath;
    if (!parent) break;
    if (parent.isBinaryExpression() || parent.isLogicalExpression() || parent.isUnaryExpression()) {
      return true;
    }
    if ((parent.isIfStatement() || parent.isConditionalExpression()) && cur.key === 'test') {
      return true;
    }
    if (parent.isCallExpression()) {
      const callee = parent.node.callee;
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        BOOLEAN_PRODUCING_MEMBER_METHODS.has(callee.property.name)
      ) {
        return true;
      }
    }
    cur = parent;
    if (cur.isFunction() || cur.isProgram()) break;
  }
  return false;
}

/** True for `req.body` / `req.query` / `req.params` used bare (no property access). */
function isBareReqCollection(node) {
  return (
    node &&
    node.type === 'MemberExpression' &&
    !node.computed &&
    node.object.type === 'Identifier' &&
    node.object.name === 'req' &&
    node.property &&
    ['body', 'query', 'params', 'headers'].includes(node.property.name)
  );
}

/**
 * Builds a one-line source snippet for a node's location, from the raw file
 * text (used for the finding's `snippet` field).
 */
function snippetForLine(lines, lineNumber) {
  if (!lineNumber || lineNumber < 1 || lineNumber > lines.length) return '';
  return lines[lineNumber - 1].trim().slice(0, 160);
}

/**
 * Checks whether a MemberExpression node is a direct HTTP-input source,
 * e.g. req.body / req.query / req.params / req.headers, at any depth
 * (req.query.username is a MemberExpression whose .object is req.query).
 */
function isHttpSourceMember(node) {
  if (!node || node.type !== 'MemberExpression') return false;
  let cursor = node;
  // Walk down to the root object, remembering the property chain.
  const props = [];
  while (cursor.type === 'MemberExpression') {
    if (!cursor.computed && cursor.property && cursor.property.name) {
      props.unshift(cursor.property.name);
    }
    cursor = cursor.object;
  }
  if (cursor.type !== 'Identifier' || cursor.name !== 'req') return false;
  const first = props[0];
  return first === 'body' || first === 'query' || first === 'params' || first === 'headers';
}

/** Checks for `process.env` or `process.env.SOMETHING`. */
function isEnvSourceMember(node) {
  if (!node || node.type !== 'MemberExpression') return false;
  const obj = node.object;
  return (
    obj &&
    obj.type === 'MemberExpression' &&
    obj.object &&
    obj.object.type === 'Identifier' &&
    obj.object.name === 'process' &&
    obj.property &&
    obj.property.name === 'env'
  ) || (
    obj &&
    obj.type === 'Identifier' &&
    obj.name === 'process' &&
    node.property &&
    node.property.name === 'env'
  );
}

/**
 * Pre-scans the file for simple local function/arrow declarations with a
 * single parameter and builds a taint-transfer summary for each, keyed by
 * function name. This is the "basic inter-procedural" pass.
 * @param {object} ast
 * @returns {Map<string, {passthrough: boolean, sanitizes: boolean, unknown: boolean}>}
 */
function buildFunctionSummaries(ast) {
  const summaries = new Map();

  function classifyReturnExpr(returnNode, paramName) {
    if (!returnNode) return { passthrough: false, sanitizes: false, unknown: true };

    if (returnNode.type === 'Identifier' && returnNode.name === paramName) {
      return { passthrough: true, sanitizes: false, unknown: false };
    }

    if (returnNode.type === 'ObjectExpression') {
      // Structured validator-style result (e.g. { valid, value }) - treat
      // as a sanitizing boundary rather than a raw passthrough.
      return { passthrough: false, sanitizes: true, unknown: false };
    }

    if (returnNode.type === 'CallExpression') {
      const callee = returnNode.callee;
      if (callee.type === 'MemberExpression' && !callee.computed) {
        const propName = callee.property.name;
        if (BOOLEAN_PRODUCING_MEMBER_METHODS.has(propName)) {
          return { passthrough: false, sanitizes: true, unknown: false, note: 'boolean validator' };
        }
        const objName = callee.object.type === 'Identifier' ? callee.object.name : null;
        const isKnownSanitizerMember = SANITIZER_MEMBER_CALLS.some(
          (entry) => entry.object === objName && entry.properties.includes(propName)
        );
        if (isKnownSanitizerMember) {
          return { passthrough: false, sanitizes: true, unknown: false };
        }
      }
      if (callee.type === 'Identifier' && SANITIZER_CALL_NAMES.has(callee.name)) {
        return { passthrough: false, sanitizes: true, unknown: false };
      }
    }

    if (
      returnNode.type === 'BinaryExpression' &&
      ['===', '!==', '==', '!=', '<', '>', '<=', '>='].includes(returnNode.operator)
    ) {
      return { passthrough: false, sanitizes: true, unknown: false, note: 'boolean comparison' };
    }

    if (returnNode.type === 'UnaryExpression' && returnNode.operator === '!') {
      return { passthrough: false, sanitizes: true, unknown: false, note: 'boolean negation' };
    }

    return { passthrough: false, sanitizes: false, unknown: true };
  }

  function findTopLevelReturn(bodyNode) {
    if (bodyNode.type !== 'BlockStatement') {
      // Arrow function with an expression body IS the return value.
      return bodyNode;
    }
    let found = null;
    for (const stmt of bodyNode.body) {
      if (stmt.type === 'ReturnStatement' && stmt.argument) {
        found = stmt.argument;
      }
    }
    return found;
  }

  function registerFunction(name, params, body) {
    if (!name || params.length !== 1 || params[0].type !== 'Identifier') return;
    const paramName = params[0].name;
    const returnExpr = findTopLevelReturn(body);
    summaries.set(name, classifyReturnExpr(returnExpr, paramName));
  }

  traverse(ast, {
    FunctionDeclaration(path) {
      if (path.node.id) {
        registerFunction(path.node.id.name, path.node.params, path.node.body);
      }
    },
    VariableDeclarator(path) {
      const init = path.node.init;
      if (
        path.node.id.type === 'Identifier' &&
        init &&
        (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression')
      ) {
        registerFunction(path.node.id.name, init.params, init.body);
      }
    }
  });

  return summaries;
}

/**
 * Core taint-check for an arbitrary expression node. Returns a taint
 * descriptor rather than a boolean so callers get a source location and a
 * human-readable path trace for the finding.
 * @param {import('@babel/traverse').NodePath} exprPath
 * @param {Map} functionSummaries
 * @returns {{tainted: boolean, sourceType?: string, sourceLine?: number, trace: string[]}}
 */
function analyzeExpression(exprPath, functionSummaries) {
  if (!exprPath || !exprPath.node) return { tainted: false, trace: [] };
  const node = exprPath.node;

  switch (node.type) {
    case 'MemberExpression': {
      if (isHttpSourceMember(node)) {
        return {
          tainted: true,
          sourceType: 'HTTP_INPUT',
          sourceLine: node.loc ? node.loc.start.line : null,
          trace: [`HTTP input at line ${node.loc ? node.loc.start.line : '?'}`]
        };
      }
      if (isEnvSourceMember(node)) {
        return {
          tainted: true,
          sourceType: 'ENV_INPUT',
          sourceLine: node.loc ? node.loc.start.line : null,
          trace: [`process.env read at line ${node.loc ? node.loc.start.line : '?'}`]
        };
      }
      // Recurse into the object for chains like path.join(req.query.x).
      return analyzeExpression(exprPath.get('object'), functionSummaries);
    }

    case 'Identifier': {
      const binding = exprPath.scope.getBinding(node.name);
      if (binding && binding.__taint && binding.__taint.tainted) {
        return {
          tainted: true,
          sourceType: binding.__taint.sourceType,
          sourceLine: binding.__taint.sourceLine,
          trace: [...binding.__taint.trace, `flows through '${node.name}' at line ${node.loc ? node.loc.start.line : '?'}`]
        };
      }
      return { tainted: false, trace: [] };
    }

    case 'TemplateLiteral': {
      const exprsPath = exprPath.get('expressions');
      for (const p of exprsPath) {
        const result = analyzeExpression(p, functionSummaries);
        if (result.tainted) {
          return { ...result, trace: [...result.trace, 'concatenated into template literal'] };
        }
      }
      return { tainted: false, trace: [] };
    }

    case 'BinaryExpression': {
      if (node.operator === '+') {
        const left = analyzeExpression(exprPath.get('left'), functionSummaries);
        if (left.tainted) return { ...left, trace: [...left.trace, 'concatenated with +'] };
        const right = analyzeExpression(exprPath.get('right'), functionSummaries);
        if (right.tainted) return { ...right, trace: [...right.trace, 'concatenated with +'] };
      }
      return { tainted: false, trace: [] };
    }

    case 'ConditionalExpression': {
      const cons = analyzeExpression(exprPath.get('consequent'), functionSummaries);
      if (cons.tainted) return { ...cons, trace: [...cons.trace, 'via ternary branch'] };
      const alt = analyzeExpression(exprPath.get('alternate'), functionSummaries);
      if (alt.tainted) return { ...alt, trace: [...alt.trace, 'via ternary branch'] };
      return { tainted: false, trace: [] };
    }

    case 'LogicalExpression': {
      const left = analyzeExpression(exprPath.get('left'), functionSummaries);
      if (left.tainted) return { ...left, trace: [...left.trace, `via '${node.operator}'`] };
      const right = analyzeExpression(exprPath.get('right'), functionSummaries);
      if (right.tainted) return { ...right, trace: [...right.trace, `via '${node.operator}'`] };
      return { tainted: false, trace: [] };
    }

    case 'CallExpression': {
      const callee = node.callee;

      // path.join(...) / path.resolve(...) preserve taint from any argument.
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'path' &&
        (callee.property.name === 'join' || callee.property.name === 'resolve')
      ) {
        const argsPath = exprPath.get('arguments');
        for (const p of argsPath) {
          const result = analyzeExpression(p, functionSummaries);
          if (result.tainted) return { ...result, trace: [...result.trace, `via path.${callee.property.name}()`] };
        }
        return { tainted: false, trace: [] };
      }

      // Known sanitizer function/method - neutralizes taint outright.
      if (callee.type === 'Identifier' && SANITIZER_CALL_NAMES.has(callee.name)) {
        return { tainted: false, trace: [], sanitizedBy: callee.name };
      }
      if (callee.type === 'MemberExpression' && !callee.computed) {
        const objName = callee.object.type === 'Identifier' ? callee.object.name : null;
        const propName = callee.property.name;
        const isKnownSanitizerMember = SANITIZER_MEMBER_CALLS.some(
          (entry) => entry.object === objName && entry.properties.includes(propName)
        );
        if (isKnownSanitizerMember || BOOLEAN_PRODUCING_MEMBER_METHODS.has(propName)) {
          return { tainted: false, trace: [], sanitizedBy: `${objName || ''}.${propName}` };
        }
      }

      // Local helper function with a known summary (basic inter-procedural).
      if (callee.type === 'Identifier' && functionSummaries.has(callee.name)) {
        const summary = functionSummaries.get(callee.name);
        if (summary.sanitizes) {
          return { tainted: false, trace: [], sanitizedBy: callee.name };
        }
        if (summary.passthrough) {
          const argsPath = exprPath.get('arguments');
          for (const p of argsPath) {
            const result = analyzeExpression(p, functionSummaries);
            if (result.tainted) return { ...result, trace: [...result.trace, `passed through '${callee.name}()'`] };
          }
        }
        // unknown summary: conservatively treat as not tainted to keep
        // false positives low, per the engine's documented trade-off.
        return { tainted: false, trace: [] };
      }

      // Unknown method call on a tainted receiver (e.g. .trim(), .toLowerCase())
      // - most string methods preserve taint, so default to propagating it.
      if (callee.type === 'MemberExpression') {
        const objResult = analyzeExpression(exprPath.get('object'), functionSummaries);
        if (objResult.tainted) {
          return { ...objResult, trace: [...objResult.trace, `passed through '.${callee.property.name || '?'}()'`] };
        }
      }

      return { tainted: false, trace: [] };
    }

    default:
      return { tainted: false, trace: [] };
  }
}

/**
 * Records a finding-shaped object. Kept separate from compliance.js's
 * public finding shape - compliance.js maps this into that shape so the
 * rest of the pipeline (sarif.js, bobguard.js, buildComplianceSummary)
 * never has to change.
 */
function makeTaintFinding(opts) {
  return {
    category: opts.category,
    confidence: opts.confidence, // 'HIGH' | 'MEDIUM' | 'LOW'
    filePath: opts.filePath,
    line: opts.line,
    snippet: opts.snippet,
    description: opts.description,
    remediation: opts.remediation,
    tags: COMPLIANCE_TAGS[opts.category] || {},
    taintPath: opts.trace && opts.trace.length ? opts.trace.join(' -> ') : `Source -> ${opts.category} sink (${opts.filePath}:${opts.line})`
  };
}

/**
 * Runs the full taint analysis over one parsed file.
 * @param {object} ast - Babel AST from parser.js
 * @param {string} filePath
 * @param {string[]} lines - the file's source, split by line (for snippets)
 * @returns {object[]} taint findings (see makeTaintFinding shape)
 */
function analyzeFile(ast, filePath, lines) {
  const findings = [];
  const functionSummaries = buildFunctionSummaries(ast);
  const rawSourceBindings = []; // for the post-pass A04 validation check

  traverse(ast, {
    VariableDeclarator(path) {
      const init = path.node.init;
      if (!init) return;

      // --- Destructuring: const { a, b } = <init>; --------------------
      // Handled separately from the plain-Identifier case below: taint
      // (or its absence) on the WHOLE init expression is propagated to
      // EVERY destructured local name. This is what makes a very common
      // real-world vulnerable idiom - `const { username, role } =
      // req.body;` - visible to the engine at all; without this, only
      // `const username = req.body.username;` would be tracked and the
      // destructured form would be silently missed.
      if (path.node.id.type === 'ObjectPattern') {
        const initResult = analyzeExpression(path.get('init'), functionSummaries);
        const initIsRawSource = isHttpSourceMember(init) || isBareReqCollection(init);

        const initIsBareReqBody =
          init.type === 'MemberExpression' &&
          !init.computed &&
          init.object.type === 'Identifier' &&
          init.object.name === 'req' &&
          init.property &&
          init.property.name === 'body';

        path.node.id.properties.forEach((prop, idx) => {
          if (prop.type !== 'ObjectProperty' || prop.value.type !== 'Identifier') return; // skip rest/nested patterns
          const localName = prop.value.name;
          const keyName = prop.key.type === 'Identifier' ? prop.key.name : (prop.key.type === 'StringLiteral' ? prop.key.value : null);
          const binding = path.scope.getBinding(localName);
          if (!binding) return;

          binding.__taint = {
            tainted: initResult.tainted,
            sourceType: initResult.sourceType,
            sourceLine: initResult.sourceLine,
            trace: initResult.trace || []
          };

          if (initIsRawSource) {
            rawSourceBindings.push({
              name: localName,
              binding,
              line: prop.loc ? prop.loc.start.line : (path.node.loc ? path.node.loc.start.line : null)
            });
          }

          if (initIsBareReqBody && keyName && MASS_ASSIGNMENT_PROPS.has(keyName.toLowerCase())) {
            const line = prop.loc ? prop.loc.start.line : null;
            findings.push(
              makeTaintFinding({
                category: 'MASS_ASSIGNMENT',
                confidence: 'HIGH',
                filePath,
                line,
                snippet: snippetForLine(lines, line),
                description: `Privileged field '${keyName}' is destructured directly from req.body.`,
                remediation: 'Never trust a client-supplied privilege field; assign it server-side only, from an authenticated/authorized source.',
                trace: [`req.body destructured for '${keyName}' at line ${line}`]
              })
            );
          }
        });
        return;
      }

      if (path.node.id.type !== 'Identifier') return;

      const result = analyzeExpression(path.get('init'), functionSummaries);
      const binding = path.scope.getBinding(path.node.id.name);
      if (binding) {
        binding.__taint = {
          tainted: result.tainted,
          sourceType: result.sourceType,
          sourceLine: result.sourceLine,
          trace: result.trace || []
        };

        // A direct, unwrapped extraction of an HTTP input collection or
        // property is a candidate OWASP-A04 finding UNLESS a later
        // reference to this binding is itself a validation guard (checked
        // in the post-pass below, once referencePaths are fully populated).
        if (isHttpSourceMember(init) || isBareReqCollection(init)) {
          rawSourceBindings.push({
            name: path.node.id.name,
            binding,
            line: init.loc ? init.loc.start.line : (path.node.loc ? path.node.loc.start.line : null)
          });
        }
      }

      // Hardcoded secret: `const <suspiciousName> = '<literal>';`
      if (
        init.type === 'StringLiteral' &&
        init.value.length >= 4 &&
        SECRET_KEY_PATTERN.test(path.node.id.name)
      ) {
        const line = path.node.loc ? path.node.loc.start.line : null;
        findings.push(
          makeTaintFinding({
            category: 'HARDCODED_SECRET',
            confidence: 'HIGH',
            filePath,
            line,
            snippet: snippetForLine(lines, line),
            description: `Possible hardcoded credential in variable '${path.node.id.name}'.`,
            remediation: 'Move secrets to environment variables or a secrets manager; never commit literal credentials to source.',
            trace: [`literal assigned to '${path.node.id.name}' at line ${line}`]
          })
        );
      }
    },

    ObjectProperty(path) {
      const keyNode = path.node.key;
      const keyName = keyNode.type === 'Identifier' ? keyNode.name : (keyNode.type === 'StringLiteral' ? keyNode.value : null);
      if (
        keyName &&
        SECRET_KEY_PATTERN.test(keyName) &&
        path.node.value.type === 'StringLiteral' &&
        path.node.value.value.length >= 4
      ) {
        const line = path.node.loc ? path.node.loc.start.line : null;
        findings.push(
          makeTaintFinding({
            category: 'HARDCODED_SECRET',
            confidence: 'HIGH',
            filePath,
            line,
            snippet: snippetForLine(lines, line),
            description: `Possible hardcoded credential in object property '${keyName}'.`,
            remediation: 'Move secrets to environment variables or a secrets manager; never commit literal credentials to source.',
            trace: [`literal assigned to property '${keyName}' at line ${line}`]
          })
        );
      }
    },

    MemberExpression(path) {
      const node = path.node;
      if (
        !node.computed &&
        node.object.type === 'MemberExpression' &&
        !node.object.computed &&
        node.object.object.type === 'Identifier' &&
        node.object.object.name === 'req' &&
        node.object.property.name === 'body' &&
        node.property &&
        MASS_ASSIGNMENT_PROPS.has(node.property.name.toLowerCase())
      ) {
        const line = node.loc ? node.loc.start.line : null;
        findings.push(
          makeTaintFinding({
            category: 'MASS_ASSIGNMENT',
            confidence: 'HIGH',
            filePath,
            line,
            snippet: snippetForLine(lines, line),
            description: `Privileged field 'req.body.${node.property.name}' is read directly from client input.`,
            remediation: 'Never trust a client-supplied privilege field; assign it server-side only, from an authenticated/authorized source.',
            trace: [`req.body.${node.property.name} read at line ${line}`]
          })
        );
      }
    },

    AssignmentExpression(path) {
      if (path.node.left.type !== 'Identifier' || path.node.operator !== '=') return;
      const result = analyzeExpression(path.get('right'), functionSummaries);
      const binding = path.scope.getBinding(path.node.left.name);
      if (binding) {
        binding.__taint = {
          tainted: result.tainted,
          sourceType: result.sourceType,
          sourceLine: result.sourceLine,
          trace: result.trace || []
        };
      }
    },

    CallExpression(path) {
      const node = path.node;
      const callee = node.callee;
      const line = node.loc ? node.loc.start.line : null;
      const argPaths = path.get('arguments');

      // --- Verbose error disclosure: any res...() chain whose argument
      // object exposes a raw `<ident>.message` property (correctly detects
      // chained calls like res.status(500).json({ details: err.message }),
      // which a naive single-call regex cannot see). ---
      if (rootsAtResIdentifier(node) && argPaths[0] && argPaths[0].node.type === 'ObjectExpression') {
        const exposesRawMessage = argPaths[0].node.properties.some(
          (prop) =>
            prop.type === 'ObjectProperty' &&
            prop.value.type === 'MemberExpression' &&
            !prop.value.computed &&
            prop.value.property &&
            prop.value.property.name === 'message'
        );
        if (exposesRawMessage) {
          findings.push(
            makeTaintFinding({
              category: 'VERBOSE_ERROR',
              confidence: 'HIGH',
              filePath,
              line,
              snippet: snippetForLine(lines, line),
              description: 'Raw exception message is returned directly in the HTTP response.',
              remediation: 'Log the full error server-side only; return a generic error message to the client.',
              trace: [`error.message exposed in response at line ${line}`]
            })
          );
        }
      }

      // --- SQL sink: db.<method>(sql, [params]) ---
      if (callee.type === 'MemberExpression' && !callee.computed && SQL_SINK_METHODS.has(callee.property.name)) {
        const queryArg = argPaths[0];
        if (queryArg) {
          const result = analyzeExpression(queryArg, functionSummaries);
          if (result.tainted) {
            findings.push(
              makeTaintFinding({
                category: 'SQL_INJECTION',
                confidence: 'HIGH',
                filePath,
                line,
                snippet: snippetForLine(lines, line),
                description: `Tainted value flows into a '${callee.property.name}()' SQL call without parameterization.`,
                remediation: 'Use a parameterized query (? placeholders) and pass tainted values via the params array instead of building the SQL string with them.',
                trace: result.trace
              })
            );
          }
        }
      }

      // sequelize.literal(...) - always unsafe if any argument is tainted.
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'sequelize' &&
        callee.property.name === 'literal'
      ) {
        for (const argPath of argPaths) {
          const result = analyzeExpression(argPath, functionSummaries);
          if (result.tainted) {
            findings.push(
              makeTaintFinding({
                category: 'SQL_INJECTION',
                confidence: 'HIGH',
                filePath,
                line,
                snippet: snippetForLine(lines, line),
                description: "Tainted value passed to 'sequelize.literal()', which performs no escaping.",
                remediation: 'Avoid sequelize.literal() with user input; use standard parameterized query builders instead.',
                trace: result.trace
              })
            );
            break;
          }
        }
      }

      // --- Command injection: exec/spawn/execFile(...) ---
      const isDirectCmdCall = callee.type === 'Identifier' && CMD_SINK_NAMES.has(callee.name);
      const isMemberCmdCall =
        callee.type === 'MemberExpression' && !callee.computed && CMD_SINK_NAMES.has(callee.property.name);
      if (isDirectCmdCall || isMemberCmdCall) {
        const firstArg = argPaths[0];
        const result = firstArg ? analyzeExpression(firstArg, functionSummaries) : { tainted: false, trace: [] };
        let tainted = result.tainted;
        let trace = result.trace;
        if (!tainted && argPaths[1] && argPaths[1].node.type === 'ArrayExpression') {
          for (const el of argPaths[1].get('elements')) {
            const r = analyzeExpression(el, functionSummaries);
            if (r.tainted) {
              tainted = true;
              trace = r.trace;
              break;
            }
          }
        }
        if (tainted) {
          findings.push(
            makeTaintFinding({
              category: 'COMMAND_INJECTION',
              confidence: 'HIGH',
              filePath,
              line,
              snippet: snippetForLine(lines, line),
              description: `Tainted value passed to '${callee.name || callee.property.name}()', which executes a shell command.`,
              remediation: 'Avoid building shell commands from user input; use an allow-list of fixed commands/args, or a library call that avoids the shell entirely.',
              trace
            })
          );
        }
      }

      // --- Code execution: eval(...) / new Function(...) handled below in NewExpression ---
      if (callee.type === 'Identifier' && callee.name === 'eval' && argPaths[0]) {
        const argNode = argPaths[0].node;
        const isLiteral = argNode.type === 'StringLiteral';
        if (!isLiteral) {
          const result = analyzeExpression(argPaths[0], functionSummaries);
          findings.push(
            makeTaintFinding({
              category: 'CODE_EXECUTION',
              confidence: result.tainted ? 'HIGH' : 'MEDIUM',
              filePath,
              line,
              snippet: snippetForLine(lines, line),
              description: "'eval()' called with a non-literal argument.",
              remediation: 'Remove eval() entirely; use JSON.parse for data or an explicit dispatch table instead of dynamic code execution.',
              trace: result.trace
            })
          );
        }
      }

      // --- Path traversal: fs.readFile(taintedPath, ...) or destructured readFile(...) ---
      const isMemberFsCall =
        callee.type === 'MemberExpression' && !callee.computed && FS_SINK_METHODS.has(callee.property.name);
      const isDirectFsCall = callee.type === 'Identifier' && FS_SINK_METHODS.has(callee.name);
      if ((isMemberFsCall || isDirectFsCall) && argPaths[0]) {
        const result = analyzeExpression(argPaths[0], functionSummaries);
        if (result.tainted) {
          findings.push(
            makeTaintFinding({
              category: 'PATH_TRAVERSAL',
              confidence: 'HIGH',
              filePath,
              line,
              snippet: snippetForLine(lines, line),
              description: `Tainted value used as a file path in '${callee.name || callee.property.name}()'.`,
              remediation: 'Resolve against a fixed base directory and reject any path that escapes it (e.g. compare path.resolve() output against the base dir) before touching the filesystem.',
              trace: result.trace
            })
          );
        }
      }

      // --- XSS / unsafe write: res.send(taintedHtml) / res.write(...) ---
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'res' &&
        XSS_SINK_METHODS.has(callee.property.name) &&
        argPaths[0]
      ) {
        const argNode = argPaths[0].node;
        const looksStringy =
          argNode.type === 'TemplateLiteral' ||
          argNode.type === 'BinaryExpression' ||
          argNode.type === 'Identifier' ||
          argNode.type === 'MemberExpression';
        if (looksStringy) {
          const result = analyzeExpression(argPaths[0], functionSummaries);
          if (result.tainted) {
            findings.push(
              makeTaintFinding({
                category: 'XSS',
                confidence: 'MEDIUM',
                filePath,
                line,
                snippet: snippetForLine(lines, line),
                description: `Tainted value written directly to the response via '${callee.property.name}()' with no escaping.`,
                remediation: 'Escape output for the target context (HTML-encode for HTML bodies) or use res.json() for structured data instead of building HTML/text manually.',
                trace: result.trace
              })
            );
          }
        }
      }
    },

    NewExpression(path) {
      const node = path.node;
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function' && node.arguments.length) {
        const line = node.loc ? node.loc.start.line : null;
        const lastArgPath = path.get(`arguments.${node.arguments.length - 1}`);
        const argNode = lastArgPath.node;
        const isLiteral = argNode.type === 'StringLiteral';
        if (!isLiteral) {
          const result = analyzeExpression(lastArgPath, functionSummaries);
          findings.push(
            makeTaintFinding({
              category: 'CODE_EXECUTION',
              confidence: result.tainted ? 'HIGH' : 'MEDIUM',
              filePath,
              line,
              snippet: snippetForLine(lines, line),
              description: "'new Function()' constructed with a non-literal body.",
              remediation: 'Remove dynamic Function construction; use an explicit dispatch table instead.',
              trace: result.trace
            })
          );
        }
      }
    }
  });

  // Second traversal for new rule types (keeps the main traversal readable
  // and avoids megamorphic CallExpression handlers).
  traverse(ast, {
    CallExpression(path) {
      const node = path.node;
      const callee = node.callee;
      const line = node.loc ? node.loc.start.line : null;
      const argPaths = path.get('arguments');

      // --- Weak crypto: crypto.createHash('md5'|'sha1') ---
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.property.name === 'createHash' &&
        argPaths[0] && argPaths[0].node.type === 'StringLiteral' &&
        WEAK_HASH_ALGORITHMS.has(argPaths[0].node.value.toLowerCase())
      ) {
        findings.push(
          makeTaintFinding({
            category: 'WEAK_CRYPTO',
            confidence: 'HIGH',
            filePath,
            line,
            snippet: snippetForLine(lines, line),
            description: `Weak hash algorithm '${argPaths[0].node.value}' used in crypto.createHash(). MD5 and SHA-1 are cryptographically broken.`,
            remediation: "Replace with a secure algorithm: use 'sha256' or 'sha512' for general hashing, or bcrypt/argon2 for password hashing.",
            trace: [`crypto.createHash('${argPaths[0].node.value}') at line ${line}`]
          })
        );
      }

      // --- Weak randomness: Math.random() (flagged as-is, not taint-dependent) ---
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'Math' &&
        callee.property.name === 'random'
      ) {
        // Only flag when the result is assigned to a variable whose name
        // suggests security-sensitive use (token, key, secret, id, nonce).
        // Walk up through chained .method() calls to find the VariableDeclarator.
        let ancestor = path.parentPath;
        while (ancestor && (ancestor.isCallExpression() || ancestor.isMemberExpression())) {
          ancestor = ancestor.parentPath;
        }
        let sensitiveContext = false;
        if (ancestor && ancestor.isVariableDeclarator() && ancestor.node.id && ancestor.node.id.type === 'Identifier') {
          sensitiveContext = /token|key|secret|nonce|salt|rand|id/i.test(ancestor.node.id.name);
        }
        if (sensitiveContext) {
          findings.push(
            makeTaintFinding({
              category: 'WEAK_CRYPTO',
              confidence: 'MEDIUM',
              filePath,
              line,
              snippet: snippetForLine(lines, line),
              description: "Math.random() is not cryptographically secure and must not be used for tokens, keys, or nonces.",
              remediation: "Use crypto.randomBytes() or crypto.randomUUID() from Node's built-in 'crypto' module for security-sensitive random values.",
              trace: [`Math.random() used in security-sensitive context at line ${line}`]
            })
          );
        }
      }

      // --- Insecure setTimeout/setInterval with a string argument ---
      if (
        callee.type === 'Identifier' &&
        (callee.name === 'setTimeout' || callee.name === 'setInterval') &&
        argPaths[0] && argPaths[0].node.type === 'StringLiteral'
      ) {
        findings.push(
          makeTaintFinding({
            category: 'INSECURE_TIMEOUT',
            confidence: 'HIGH',
            filePath,
            line,
            snippet: snippetForLine(lines, line),
            description: `'${callee.name}()' called with a string argument, which is evaluated as code (implicit eval).`,
            remediation: `Pass a function reference instead: ${callee.name}(() => { /* code */ }, delay).`,
            trace: [`${callee.name}(string) at line ${line}`]
          })
        );
      }

      // --- Log injection / sensitive data exposure ---
      // Flags: console.log/error/warn/info/debug/trace(...) where any argument
      // is a direct HTTP input source OR an object property whose key matches
      // a sensitive field name.
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'console' &&
        LOG_METHODS.has(callee.property.name)
      ) {
        for (const argPath of argPaths) {
          const argNode = argPath.node;

          // Direct HTTP input piped to log: console.log(req.body)
          if (isHttpSourceMember(argNode) || isBareReqCollection(argNode)) {
            findings.push(
              makeTaintFinding({
                category: 'LOG_SENSITIVE',
                confidence: 'HIGH',
                filePath,
                line,
                snippet: snippetForLine(lines, line),
                description: `Raw HTTP request data (${argNode.property ? 'req.' + argNode.property.name : 'req collection'}) is logged directly, potentially exposing passwords or tokens.`,
                remediation: 'Never log raw request bodies or headers; redact or omit sensitive fields before logging.',
                trace: [`console.${callee.property.name}(req.*) at line ${line}`]
              })
            );
            break;
          }

          // Object literal with sensitive key: console.log({ password: x })
          if (argNode.type === 'ObjectExpression') {
            for (const prop of argNode.properties) {
              if (prop.type !== 'ObjectProperty') continue;
              const keyName = prop.key.type === 'Identifier' ? prop.key.name
                : (prop.key.type === 'StringLiteral' ? prop.key.value : null);
              if (keyName && SENSITIVE_LOG_FIELDS.has(keyName.toLowerCase())) {
                findings.push(
                  makeTaintFinding({
                    category: 'LOG_SENSITIVE',
                    confidence: 'HIGH',
                    filePath,
                    line,
                    snippet: snippetForLine(lines, line),
                    description: `Sensitive field '${keyName}' is included in a console.${callee.property.name}() call.`,
                    remediation: 'Omit or redact sensitive fields before logging.',
                    trace: [`console.${callee.property.name}({${keyName}: ...}) at line ${line}`]
                  })
                );
                break;
              }
            }
          }
        }
      }
    },

    // --- High-entropy string literal anywhere in the file ---
    StringLiteral(path) {
      const value = path.node.value;
      if (!isHighEntropySecret(value)) return;
      const line = path.node.loc ? path.node.loc.start.line : null;

      // Avoid double-reporting secrets already caught by HARDCODED_SECRET
      // (which matches on variable name). HIGH_ENTROPY_SECRET fires when
      // the literal value itself looks like a token regardless of name.
      findings.push(
        makeTaintFinding({
          category: 'HIGH_ENTROPY_SECRET',
          confidence: 'HIGH',
          filePath,
          line,
          snippet: snippetForLine(lines, line),
          description: 'High-entropy string literal detected that matches a known secret pattern (JWT, AWS key, Stripe key, or high-entropy base64 blob).',
          remediation: 'Remove hardcoded secrets; load them from environment variables or a secrets manager at runtime.',
          trace: [`high-entropy literal at line ${line}`]
        })
      );
    }
  });

  // Post-pass: for every raw-source declaration, check whether ANY of its
  // references (babel's own reference tracking, not hand-rolled) sits in a
  // validating position. Only flag OWASP-A04 when none do - this is what
  // lets a variable that IS validated downstream (even without a dedicated
  // sanitizer function) clear the finding, unlike a pure "was this line a
  // direct req.* extraction" regex check.
  rawSourceBindings.forEach(({ name, binding, line }) => {
    const hasGuard = (binding.referencePaths || []).some((refPath) => isValidationUsage(refPath));
    if (!hasGuard) {
      findings.push(
        makeTaintFinding({
          category: 'UNVALIDATED_INPUT',
          confidence: 'MEDIUM',
          filePath,
          line,
          snippet: snippetForLine(lines, line),
          description: `'${name}' is derived directly from request input and is never checked (no comparison, typeof guard, or validator call found) before use.`,
          remediation: 'Add an explicit type/format/presence check before using this value.',
          trace: [`unguarded request input assigned to '${name}' at line ${line}`]
        })
      );
    }
  });

  return findings;
}

module.exports = {
  analyzeFile,
  analyzeExpression,
  buildFunctionSummaries,
  isHttpSourceMember,
  isEnvSourceMember,
  COMPLIANCE_TAGS
};
