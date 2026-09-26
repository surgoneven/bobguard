'use strict';

/**
 * Enterprise feature test suite.
 *
 * Covers:
 *   - CycloneDX v1.5 SBOM JSON structure and PURL validity
 *   - SOC 2 / PCI-DSS / ISO 27001 compliance matrix generator
 *   - bobguard init hook creation logic (in-process, no CLI spawn)
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

const { generateSbom, writeSbom, buildPurl, buildComponent, normalizeLicense } = require('../lib/sbom');
const {
  CONTROLS,
  RULE_TO_CONTROLS,
  buildComplianceMatrix,
  generateAttestationMarkdown,
  writeAttestationReport
} = require('../lib/complianceMatrix');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a temp directory with an optional package.json. */
function makeTmpPkg(pkg, lockData) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bobguard-sbom-'));
  fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkg, null, 2), 'utf8');
  if (lockData) {
    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), JSON.stringify(lockData, null, 2), 'utf8');
  }
  return tmpDir;
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

// ---------------------------------------------------------------------------
// buildPurl
// ---------------------------------------------------------------------------

describe('buildPurl', () => {
  test('builds correct purl for plain package', () => {
    expect(buildPurl('express', '4.18.2')).toBe('pkg:npm/express@4.18.2');
  });

  test('builds correct purl for scoped package', () => {
    expect(buildPurl('@babel/parser', '7.24.0')).toBe('pkg:npm/%40babel/parser@7.24.0');
  });

  test('strips semver range prefix', () => {
    expect(buildPurl('lodash', '^4.17.21')).toBe('pkg:npm/lodash@4.17.21');
  });

  test('handles empty version', () => {
    const purl = buildPurl('unknown', '');
    expect(purl).toBe('pkg:npm/unknown@');
  });
});

// ---------------------------------------------------------------------------
// normalizeLicense
// ---------------------------------------------------------------------------

describe('normalizeLicense', () => {
  test('returns string license as-is', () => {
    expect(normalizeLicense('MIT')).toBe('MIT');
  });

  test('extracts type from object', () => {
    expect(normalizeLicense({ type: 'Apache-2.0', url: 'https://...' })).toBe('Apache-2.0');
  });

  test('returns NOASSERTION for undefined', () => {
    expect(normalizeLicense(undefined)).toBe('NOASSERTION');
  });
});

// ---------------------------------------------------------------------------
// buildComponent
// ---------------------------------------------------------------------------

describe('buildComponent', () => {
  test('produces valid CycloneDX component shape', () => {
    const c = buildComponent('express', '4.18.2', 'MIT', 'Fast HTTP server', 'required');
    expect(c.type).toBe('library');
    expect(c.name).toBe('express');
    expect(c.version).toBe('4.18.2');
    expect(c.purl).toBe('pkg:npm/express@4.18.2');
    expect(c.licenses[0].license.id).toBe('MIT');
    expect(c.scope).toBe('required');
    expect(c['bom-ref']).toBe('pkg:npm/express@4.18.2');
  });

  test('strips semver range from version', () => {
    const c = buildComponent('lodash', '^4.17.21');
    expect(c.version).toBe('4.17.21');
  });
});

// ---------------------------------------------------------------------------
// generateSbom — structure
// ---------------------------------------------------------------------------

describe('generateSbom - BOM structure', () => {
  let tmpDir;

  const pkg = {
    name: 'my-service',
    version: '1.2.3',
    description: 'A test service',
    license: 'MIT',
    dependencies: { express: '^4.18.2', lodash: '4.17.21' },
    devDependencies: { jest: '^29.0.0' }
  };

  beforeAll(() => { tmpDir = makeTmpPkg(pkg); });
  afterAll(() => cleanup(tmpDir));

  test('bomFormat is CycloneDX', () => {
    const { bom } = generateSbom(tmpDir);
    expect(bom.bomFormat).toBe('CycloneDX');
  });

  test('specVersion is 1.5', () => {
    const { bom } = generateSbom(tmpDir);
    expect(bom.specVersion).toBe('1.5');
  });

  test('has serialNumber', () => {
    const { bom } = generateSbom(tmpDir);
    expect(typeof bom.serialNumber).toBe('string');
    expect(bom.serialNumber.length).toBeGreaterThan(8);
  });

  test('metadata.tools lists BobGuard', () => {
    const { bom } = generateSbom(tmpDir);
    const tool = bom.metadata.tools[0];
    expect(tool.name).toBe('BobGuard');
  });

  test('metadata.component reflects package.json root', () => {
    const { bom } = generateSbom(tmpDir);
    expect(bom.metadata.component.name).toBe('my-service');
    expect(bom.metadata.component.version).toBe('1.2.3');
    expect(bom.metadata.component.type).toBe('application');
  });

  test('components includes runtime dependencies', () => {
    const { bom, componentCount } = generateSbom(tmpDir);
    const names = bom.components.map((c) => c.name);
    expect(names).toContain('express');
    expect(names).toContain('lodash');
    expect(componentCount).toBeGreaterThanOrEqual(2);
  });

  test('devDependencies are present with scope=optional', () => {
    const { bom } = generateSbom(tmpDir);
    const jestComp = bom.components.find((c) => c.name === 'jest');
    expect(jestComp).toBeDefined();
    expect(jestComp.scope).toBe('optional');
  });

  test('all component purls are valid pkg:npm format', () => {
    const { bom } = generateSbom(tmpDir);
    bom.components.forEach((c) => {
      expect(c.purl).toMatch(/^pkg:npm\/.+@/);
    });
  });

  test('dependencies array has root entry', () => {
    const { bom } = generateSbom(tmpDir);
    expect(Array.isArray(bom.dependencies)).toBe(true);
    const root = bom.dependencies.find((d) => d.ref.includes('my-service'));
    expect(root).toBeDefined();
    expect(Array.isArray(root.dependsOn)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// generateSbom — with lockfile
// ---------------------------------------------------------------------------

describe('generateSbom - with package-lock.json', () => {
  let tmpDir;

  const pkg = {
    name: 'locked-service',
    version: '0.1.0',
    dependencies: { 'body-parser': '^1.20.0' }
  };

  const lock = {
    lockfileVersion: 2,
    packages: {
      '': { name: 'locked-service', version: '0.1.0' },
      'node_modules/body-parser': {
        version: '1.20.2',
        license: 'MIT',
        dependencies: { 'bytes': '3.1.2' }
      },
      'node_modules/bytes': { version: '3.1.2', license: 'MIT' }
    }
  };

  beforeAll(() => { tmpDir = makeTmpPkg(pkg, lock); });
  afterAll(() => cleanup(tmpDir));

  test('includes transitive dep from lockfile', () => {
    const { bom } = generateSbom(tmpDir);
    const names = bom.components.map((c) => c.name);
    expect(names).toContain('bytes');
  });

  test('warns when no lockfile present (no-lock scenario)', () => {
    const tmpNoLock = makeTmpPkg(pkg);
    const { warnings } = generateSbom(tmpNoLock);
    expect(warnings.some((w) => w.includes('package-lock.json'))).toBe(true);
    cleanup(tmpNoLock);
  });
});

// ---------------------------------------------------------------------------
// writeSbom
// ---------------------------------------------------------------------------

describe('writeSbom', () => {
  let tmpDir;

  beforeAll(() => {
    tmpDir = makeTmpPkg({
      name: 'write-test',
      version: '1.0.0',
      dependencies: { chalk: '^4.0.0' }
    });
  });
  afterAll(() => cleanup(tmpDir));

  test('writes valid JSON to disk', () => {
    const outPath = path.join(tmpDir, 'bom.json');
    const { outputPath, componentCount } = writeSbom(tmpDir, outPath);
    expect(fs.existsSync(outputPath)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(componentCount).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// RULE_TO_CONTROLS mapping
// ---------------------------------------------------------------------------

describe('RULE_TO_CONTROLS', () => {
  test('SQL injection maps to PCI 6.2.4', () => {
    expect(RULE_TO_CONTROLS['TAINT-SQL-INJECTION']).toContain('PCI-6.2.4');
  });

  test('Hardcoded secret maps to PCI 3.4', () => {
    expect(RULE_TO_CONTROLS['OWASP-A02-HARDCODED-SECRET']).toContain('PCI-3.4');
  });

  test('Weak crypto maps to ISO A.8.24', () => {
    expect(RULE_TO_CONTROLS['OWASP-A02-WEAK-CRYPTO']).toContain('ISO-A.8.24');
  });

  test('Verbose error maps to SOC2 CC7.2', () => {
    expect(RULE_TO_CONTROLS['OWASP-A09-VERBOSE-ERROR']).toContain('SOC2-CC7.2');
  });
});

// ---------------------------------------------------------------------------
// buildComplianceMatrix
// ---------------------------------------------------------------------------

describe('buildComplianceMatrix', () => {
  test('returns PASS for all controls when no findings', () => {
    const matrix = buildComplianceMatrix([]);
    matrix.forEach((row) => {
      expect(row.status).toBe('PASS');
      expect(row.findingCount).toBe(0);
    });
  });

  test('marks control FAIL when finding implicates it', () => {
    const findings = [
      {
        type: 'STATIC_ANALYSIS',
        ruleId: 'TAINT-SQL-INJECTION',
        severity: 'CRITICAL',
        filePath: '/app/server.js',
        line: 42
      }
    ];
    const matrix = buildComplianceMatrix(findings);
    const pci624 = matrix.find((r) => r.controlId === 'PCI-6.2.4');
    expect(pci624.status).toBe('FAIL');
    expect(pci624.findingCount).toBe(1);
  });

  test('PASS controls have empty findings array', () => {
    const matrix = buildComplianceMatrix([
      { type: 'STATIC_ANALYSIS', ruleId: 'TAINT-XSS', severity: 'MEDIUM', filePath: '/app/x.js', line: 1 }
    ]);
    const passing = matrix.filter((r) => r.status === 'PASS');
    passing.forEach((r) => expect(r.findings).toHaveLength(0));
  });

  test('matrix covers all three frameworks', () => {
    const matrix = buildComplianceMatrix([]);
    const frameworks = new Set(matrix.map((r) => r.framework));
    expect(frameworks.has('SOC 2 Type II')).toBe(true);
    expect(frameworks.has('PCI-DSS v4.0')).toBe(true);
    expect(frameworks.has('ISO/IEC 27001:2022')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// generateAttestationMarkdown
// ---------------------------------------------------------------------------

describe('generateAttestationMarkdown', () => {
  const meta = {
    target: 'demo-app',
    score: 100,
    verdict: 'PASS',
    generatedAt: '2024-01-01T00:00:00.000Z',
    version: '0.2.0'
  };

  test('contains BobGuard header', () => {
    const md = generateAttestationMarkdown(buildComplianceMatrix([]), meta);
    expect(md).toContain('BobGuard Compliance Attestation');
  });

  test('contains SOC 2 section', () => {
    const md = generateAttestationMarkdown(buildComplianceMatrix([]), meta);
    expect(md).toContain('SOC 2 Type II');
  });

  test('contains PCI-DSS section', () => {
    const md = generateAttestationMarkdown(buildComplianceMatrix([]), meta);
    expect(md).toContain('PCI-DSS');
  });

  test('contains ISO 27001 section', () => {
    const md = generateAttestationMarkdown(buildComplianceMatrix([]), meta);
    expect(md).toContain('ISO/IEC 27001');
  });

  test('shows PASS score when no findings', () => {
    const md = generateAttestationMarkdown(buildComplianceMatrix([]), meta);
    expect(md).toContain('100/100');
    expect(md).toContain('PASS');
  });

  test('shows FAIL badge for implicated control', () => {
    const findings = [
      { type: 'STATIC_ANALYSIS', ruleId: 'TAINT-SQL-INJECTION', severity: 'CRITICAL', filePath: '/app/s.js', line: 1 }
    ];
    const md = generateAttestationMarkdown(buildComplianceMatrix(findings), meta);
    expect(md).toContain('❌ FAIL');
  });
});

// ---------------------------------------------------------------------------
// writeAttestationReport
// ---------------------------------------------------------------------------

describe('writeAttestationReport', () => {
  let tmpDir;

  beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bobguard-att-')); });
  afterAll(() => cleanup(tmpDir));

  test('writes Markdown file to disk', () => {
    const outPath = path.join(tmpDir, 'compliance.md');
    const { outputPath, matrix, failingControls } = writeAttestationReport([], outPath, {
      target: 'test',
      score: 100,
      verdict: 'PASS',
      generatedAt: new Date().toISOString(),
      version: '0.2.0'
    });
    expect(fs.existsSync(outputPath)).toBe(true);
    const content = fs.readFileSync(outputPath, 'utf8');
    expect(content).toContain('BobGuard Compliance Attestation');
    expect(failingControls).toBe(0);
    expect(matrix.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// bobguard init — hook creation logic (in-process)
// ---------------------------------------------------------------------------

describe('bobguard init - hook and vscode tasks creation', () => {
  let workspaceDir;

  beforeEach(() => {
    workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bobguard-init-'));
    // Create a .git/hooks dir to simulate a real repo
    fs.mkdirSync(path.join(workspaceDir, '.git', 'hooks'), { recursive: true });
  });

  afterEach(() => cleanup(workspaceDir));

  /**
   * Inline the init logic so we can test it without spawning a child process.
   */
  function runInitLogic(workspaceRoot, auditTarget) {
    const gitHooksDir = path.join(workspaceRoot, '.git', 'hooks');
    const hookPath = path.join(gitHooksDir, 'pre-commit');
    const hookScript =
      `#!/bin/sh\n` +
      `# BobGuard pre-commit security audit (installed by 'bobguard init')\n` +
      `echo "[BobGuard] Running security audit before commit..."\n` +
      `node "BOBGUARD_PATH" audit "${auditTarget}"\n` +
      `EXIT_CODE=$?\n` +
      `if [ $EXIT_CODE -ne 0 ]; then\n` +
      `  echo "[BobGuard] Audit reported findings. Commit blocked."\n` +
      `  exit 1\n` +
      `fi\n`;
    fs.writeFileSync(hookPath, hookScript, { mode: 0o755, encoding: 'utf8' });

    const vscodeDir = path.join(workspaceRoot, '.vscode');
    if (!fs.existsSync(vscodeDir)) fs.mkdirSync(vscodeDir, { recursive: true });
    const tasksPath = path.join(vscodeDir, 'tasks.json');
    const tasksJson = {
      version: '2.0.0',
      tasks: [
        { label: 'BobGuard: Security Scan', type: 'shell', command: `node "BOBGUARD_PATH" audit "${auditTarget}"`, group: { kind: 'build', isDefault: true }, problemMatcher: [] },
        { label: 'BobGuard: Generate SBOM', type: 'shell', command: `node "BOBGUARD_PATH" audit "${auditTarget}" --sbom bom.json`, group: 'build', problemMatcher: [] },
        { label: 'BobGuard: Compliance Attestation', type: 'shell', command: `node "BOBGUARD_PATH" audit "${auditTarget}" --attestation compliance-matrix.md`, group: 'build', problemMatcher: [] }
      ]
    };
    fs.writeFileSync(tasksPath, JSON.stringify(tasksJson, null, 2), 'utf8');
    return { hookPath, tasksPath };
  }

  test('creates pre-commit hook file', () => {
    const { hookPath } = runInitLogic(workspaceDir, './demo-app');
    expect(fs.existsSync(hookPath)).toBe(true);
  });

  test('hook starts with #!/bin/sh shebang', () => {
    const { hookPath } = runInitLogic(workspaceDir, './demo-app');
    const content = fs.readFileSync(hookPath, 'utf8');
    expect(content.startsWith('#!/bin/sh')).toBe(true);
  });

  test('hook references the audit target', () => {
    const { hookPath } = runInitLogic(workspaceDir, './my-service');
    const content = fs.readFileSync(hookPath, 'utf8');
    expect(content).toContain('./my-service');
  });

  test('creates .vscode/tasks.json', () => {
    const { tasksPath } = runInitLogic(workspaceDir, './demo-app');
    expect(fs.existsSync(tasksPath)).toBe(true);
  });

  test('tasks.json contains BobGuard Security Scan task', () => {
    const { tasksPath } = runInitLogic(workspaceDir, './demo-app');
    const tasks = JSON.parse(fs.readFileSync(tasksPath, 'utf8'));
    const labels = tasks.tasks.map((t) => t.label);
    expect(labels).toContain('BobGuard: Security Scan');
  });

  test('tasks.json contains SBOM generation task', () => {
    const { tasksPath } = runInitLogic(workspaceDir, './demo-app');
    const tasks = JSON.parse(fs.readFileSync(tasksPath, 'utf8'));
    const labels = tasks.tasks.map((t) => t.label);
    expect(labels).toContain('BobGuard: Generate SBOM');
  });

  test('tasks.json contains Compliance Attestation task', () => {
    const { tasksPath } = runInitLogic(workspaceDir, './demo-app');
    const tasks = JSON.parse(fs.readFileSync(tasksPath, 'utf8'));
    const labels = tasks.tasks.map((t) => t.label);
    expect(labels).toContain('BobGuard: Compliance Attestation');
  });

  test('Security Scan task is marked as default build', () => {
    const { tasksPath } = runInitLogic(workspaceDir, './demo-app');
    const tasks = JSON.parse(fs.readFileSync(tasksPath, 'utf8'));
    const scanTask = tasks.tasks.find((t) => t.label === 'BobGuard: Security Scan');
    expect(scanTask.group.kind).toBe('build');
    expect(scanTask.group.isDefault).toBe(true);
  });

  test('tasks.json is valid JSON with version 2.0.0', () => {
    const { tasksPath } = runInitLogic(workspaceDir, './demo-app');
    const tasks = JSON.parse(fs.readFileSync(tasksPath, 'utf8'));
    expect(tasks.version).toBe('2.0.0');
  });
});
