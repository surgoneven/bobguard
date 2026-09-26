#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { Command } = require('commander');
const chalk = require('chalk');

const { analyzeDependencies, readSourceFiles } = require('../lib/analyzer');
const { evaluateOwaspRules, buildComplianceSummary } = require('../lib/compliance');
const { runAutoFix } = require('../lib/fixer');
const { runTestSuite, detectRegression } = require('../lib/runner');
const { writeSarifReport } = require('../lib/sarif');
const { writeReport } = require('../lib/reporter');
const { writeSbom } = require('../lib/sbom');
const { writeAttestationReport } = require('../lib/complianceMatrix');

const program = new Command();

program
  .name('bobguard')
  .description('BobGuard - Autonomous Developer Workflow & Release Readiness Orchestrator')
  .version('0.2.0');

function severityColor(severity, text) {
  switch (severity) {
    case 'CRITICAL':
      return chalk.bgRed.white.bold(text);
    case 'HIGH':
      return chalk.red.bold(text);
    case 'MEDIUM':
      return chalk.yellow(text);
    case 'LOW':
      return chalk.gray(text);
    default:
      return text;
  }
}

/**
 * Core scan logic shared by audit/report/fix/release. Does not print;
 * callers decide how to render results for their command.
 * @param {string} resolvedTarget
 * @returns {{depResult: object, sourceFiles: object[], staticFindings: object[], allFindings: object[], summary: object}}
 */
function scanTarget(resolvedTarget) {
  const depResult = analyzeDependencies(resolvedTarget);
  const sourceFiles = readSourceFiles(resolvedTarget);
  const staticFindings = evaluateOwaspRules(sourceFiles);
  const allFindings = [...(depResult.findings || []), ...staticFindings];
  const summary = buildComplianceSummary(allFindings);
  return { depResult, sourceFiles, staticFindings, allFindings, summary };
}

function printFindings(allFindings) {
  if (allFindings.length === 0) {
    console.log(chalk.green.bold('  No findings. Clean bill of health.\n'));
    return;
  }

  allFindings
    .slice()
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return order[a.severity] - order[b.severity];
    })
    .forEach((f) => {
      const label = severityColor(f.severity, `[${f.severity}]`);
      if (f.type === 'DEPENDENCY') {
        console.log(
          `  ${label} ${chalk.bold(f.package)}@${f.declaredVersion} - ${f.advisory}` +
          (f.cve ? chalk.gray(` (${f.cve})`) : '')
        );
      } else {
        const relPath = path.relative(process.cwd(), f.filePath).replace(/\\/g, '/');
        console.log(
          `  ${label} ${chalk.bold(f.ruleId)} ${chalk.gray(relPath + ':' + f.line)}\n` +
          `      ${f.description}\n` +
          `      ${chalk.gray('fix: ' + f.remediation)}`
        );
      }
    });
  console.log('');
}

function printSummary(summary) {
  console.log(chalk.bold('  Summary:'));
  console.log(`    Total findings:        ${summary.totalFindings}`);
  console.log(`    Critical / High / Med / Low: ${summary.bySeverity.CRITICAL} / ${summary.bySeverity.HIGH} / ${summary.bySeverity.MEDIUM} / ${summary.bySeverity.LOW}`);
  console.log(`    Release readiness score: ${summary.releaseReadinessScore}/100`);

  const verdictColor =
    summary.verdict === 'BLOCK' ? chalk.bgRed.white.bold :
    summary.verdict === 'WARN' ? chalk.yellow.bold :
    chalk.green.bold;
  console.log(`    Verdict: ${verdictColor(summary.verdict)}\n`);
}

function runAudit(targetDir) {
  const resolvedTarget = path.resolve(process.cwd(), targetDir);

  if (!fs.existsSync(resolvedTarget)) {
    console.error(chalk.red(`Target directory not found: ${resolvedTarget}`));
    process.exitCode = 1;
    return null;
  }

  console.log(chalk.cyan.bold(`\nBobGuard audit -> ${resolvedTarget}\n`));

  const { depResult, sourceFiles, allFindings, summary } = scanTarget(resolvedTarget);

  if (depResult.error) {
    console.log(chalk.yellow(`  [deps] ${depResult.error}`));
  } else {
    console.log(chalk.cyan(`  [deps] scanned ${depResult.scanned} package(s)`));
  }
  console.log(chalk.cyan(`  [static] scanned ${sourceFiles.length} source file(s)\n`));

  printFindings(allFindings);
  printSummary(summary);

  return { target: resolvedTarget, findings: allFindings, summary };
}

/**
 * Builds the portable report object used by all output formats.
 */
function buildReportData(auditResult, resolvedTarget) {
  const normalizedFindings = auditResult.findings.map((f) => {
    if (f.type === 'STATIC_ANALYSIS' && f.filePath) {
      return Object.assign({}, f, { filePath: path.relative(process.cwd(), f.filePath).replace(/\\/g, '/') });
    }
    return f;
  });
  return {
    tool: 'bobguard',
    version: '0.2.0',
    target: path.relative(process.cwd(), auditResult.target).replace(/\\/g, '/'),
    _resolvedTarget: resolvedTarget,
    generatedAt: auditResult.summary.generatedAt,
    summary: auditResult.summary,
    findings: normalizedFindings
  };
}

/** Returns a sensible default output filename for a given format. */
function defaultOutputName(format) {
  switch (format) {
    case 'html':  return 'bobguard-report.html';
    case 'md':    return 'bobguard-report.md';
    case 'sarif': return 'bobguard-results.sarif.json';
    default:      return 'bobguard-report.json';
  }
}

function runFix(targetDir) {
  const resolvedTarget = path.resolve(process.cwd(), targetDir);

  if (!fs.existsSync(resolvedTarget)) {
    console.error(chalk.red(`Target directory not found: ${resolvedTarget}`));
    process.exitCode = 1;
    return null;
  }

  console.log(chalk.cyan.bold(`\nBobGuard fix -> ${resolvedTarget}\n`));

  console.log(chalk.bold('  [1/3] Running pre-fix test baseline...'));
  const beforeTests = runTestSuite(resolvedTarget);
  if (!beforeTests.ran) {
    console.log(chalk.yellow(`    skipped: ${beforeTests.error}`));
  } else {
    console.log(`    ${beforeTests.passed ? chalk.green('PASS') : chalk.red('FAIL')} ` +
      `(${beforeTests.metrics.numPassedTests}/${beforeTests.metrics.numTotalTests} tests, ${beforeTests.durationMs}ms)`);
  }

  console.log(chalk.bold('\n  [2/3] Applying auto-fixes...'));
  const fixResult = runAutoFix(resolvedTarget);
  if (fixResult.summary.filesChanged === 0) {
    console.log('    No applicable fixes found (nothing matched known vulnerable patterns).');
  } else {
    console.log(chalk.green(`    ${fixResult.summary.filesChanged} file(s) patched:`));
    fixResult.summary.notes.forEach((note) => console.log(`      - ${note}`));
    console.log(chalk.gray('\n' + fixResult.combinedDiff));
  }

  console.log(chalk.bold('  [3/3] Running post-fix test suite...'));
  const afterTests = runTestSuite(resolvedTarget);
  if (!afterTests.ran) {
    console.log(chalk.yellow(`    skipped: ${afterTests.error}`));
  } else {
    console.log(`    ${afterTests.passed ? chalk.green('PASS') : chalk.red('FAIL')} ` +
      `(${afterTests.metrics.numPassedTests}/${afterTests.metrics.numTotalTests} tests, ${afterTests.durationMs}ms)`);
  }

  const regression = detectRegression(beforeTests, afterTests);
  console.log(regression.regressed ? chalk.red.bold(`\n  REGRESSION: ${regression.details}\n`) : chalk.green(`\n  ${regression.details}\n`));

  return { target: resolvedTarget, fixResult, beforeTests, afterTests, regression };
}

program
  .command('audit')
  .description('Scan a target directory for dependency and OWASP Top 10 findings')
  .argument('[targetDir]', 'path to the microservice/repo to audit')
  .option('-t, --target <dir>', 'target directory (alternative to positional argument)')
  .option('-f, --format <fmt>', 'output format: json|html|md|sarif (omit to print to stdout only)')
  .option('-o, --out <file>', 'write report to this file (default name derived from format)')
  .option('--sbom [file]', 'generate a CycloneDX v1.5 SBOM (default: bom.json)')
  .option('--attestation [file]', 'generate a compliance attestation doc (default: compliance-matrix.md)')
  .action((targetDirArg, options) => {
    const targetDir = targetDirArg || options.target;
    if (!targetDir) {
      console.error(chalk.red('Error: a target directory is required (positional arg or --target <dir>)'));
      process.exitCode = 1;
      return;
    }
    const result = runAudit(targetDir);
    if (!result) return;

    const resolvedTarget = path.resolve(process.cwd(), targetDir);

    if (options.format) {
      const fmt = options.format.toLowerCase();
      const outFile = options.out || defaultOutputName(fmt);
      const outputPath = path.resolve(process.cwd(), outFile);
      const reportData = buildReportData(result, resolvedTarget);
      writeReport(fmt, reportData, outputPath, { writeSarifReport });
      console.log(chalk.cyan.bold(`Report (${fmt}) written -> ${outputPath}\n`));
    }

    if (options.sbom !== undefined) {
      const sbomFile = (typeof options.sbom === 'string' && options.sbom) ? options.sbom : 'bom.json';
      try {
        const sbomResult = writeSbom(resolvedTarget, path.resolve(process.cwd(), sbomFile));
        console.log(chalk.cyan.bold(`SBOM (CycloneDX 1.5) written -> ${sbomResult.outputPath} (${sbomResult.componentCount} component(s))\n`));
        sbomResult.warnings.forEach((w) => console.log(chalk.yellow(`  [sbom] ${w}`)));
      } catch (e) {
        console.error(chalk.red(`  [sbom] ${e.message}`));
      }
    }

    if (options.attestation !== undefined) {
      const attFile = (typeof options.attestation === 'string' && options.attestation) ? options.attestation : 'compliance-matrix.md';
      const attResult = writeAttestationReport(
        result.findings,
        path.resolve(process.cwd(), attFile),
        {
          target: path.relative(process.cwd(), resolvedTarget).replace(/\\/g, '/'),
          score: result.summary.releaseReadinessScore,
          verdict: result.summary.verdict,
          generatedAt: result.summary.generatedAt,
          version: '0.2.0'
        }
      );
      console.log(chalk.cyan.bold(`Attestation report written -> ${attResult.outputPath} (${attResult.failingControls} control(s) failing)\n`));
    }
  });

program
  .command('report')
  .description('Run an audit and write a compliance report to disk')
  .argument('<targetDir>', 'path to the microservice/repo to audit')
  .option('-f, --format <fmt>', 'output format: json|html|md|sarif', 'json')
  .option('-o, --output <file>', 'output report path (default derived from format)')
  .action((targetDir, options) => {
    const result = runAudit(targetDir);
    if (!result) return;

    const fmt = (options.format || 'json').toLowerCase();
    const resolvedTarget = path.resolve(process.cwd(), targetDir);
    const outFile = options.output || defaultOutputName(fmt);
    const outputPath = path.resolve(process.cwd(), outFile);
    const reportData = buildReportData(result, resolvedTarget);
    writeReport(fmt, reportData, outputPath, { writeSarifReport });
    console.log(chalk.cyan.bold(`Report (${fmt}) written -> ${outputPath}\n`));
  });

program
  .command('fix')
  .description('Apply auto-fixes for known findings and re-run the test suite')
  .argument('<targetDir>', 'path to the microservice/repo to fix')
  .option('-i, --interactive', 'confirm each patch before applying it')
  .action((targetDir, options) => {
    if (options.interactive) {
      runFixInteractive(targetDir);
    } else {
      runFix(targetDir);
    }
  });

program
  .command('release')
  .description('Full pipeline: audit -> fix -> test -> SARIF report -> release verdict')
  .argument('<targetDir>', 'path to the microservice/repo to process')
  .option('-o, --output <file>', 'output SARIF report path', 'bobguard-results.sarif.json')
  .action((targetDir, options) => {
    const resolvedTarget = path.resolve(process.cwd(), targetDir);
    if (!fs.existsSync(resolvedTarget)) {
      console.error(chalk.red(`Target directory not found: ${resolvedTarget}`));
      process.exitCode = 1;
      return;
    }

    console.log(chalk.magenta.bold(`\n=== BobGuard release pipeline -> ${resolvedTarget} ===\n`));

    console.log(chalk.bold.underline('Stage A: Pre-fix audit'));
    const preAudit = runAudit(targetDir);
    if (!preAudit) return;

    console.log(chalk.bold.underline('Stage B: Auto-fix + regression test'));
    const fixOutcome = runFix(targetDir);
    if (!fixOutcome) return;

    console.log(chalk.bold.underline('Stage C: Post-fix audit'));
    const postAudit = runAudit(targetDir);
    if (!postAudit) return;

    console.log(chalk.bold.underline('Stage D: SARIF export'));
    const sarifPath = path.resolve(process.cwd(), options.output);
    const sarifResult = writeSarifReport(postAudit.findings, sarifPath, { repoRoot: resolvedTarget });
    console.log(chalk.cyan(`  SARIF report written -> ${sarifResult.outputPath} (${sarifResult.resultCount} result(s))\n`));

    console.log(chalk.bold.underline('Stage E: Release verdict'));
    let verdict = postAudit.summary.verdict;
    const reasons = [];

    if (fixOutcome.regression.regressed) {
      verdict = 'BLOCK';
      reasons.push(`Auto-fix introduced a test regression: ${fixOutcome.regression.details}`);
    }
    if (fixOutcome.afterTests.ran && !fixOutcome.afterTests.passed) {
      verdict = 'BLOCK';
      reasons.push('Post-fix test suite is failing.');
    }
    if (postAudit.summary.bySeverity.CRITICAL > 0) {
      verdict = 'BLOCK';
      reasons.push(`${postAudit.summary.bySeverity.CRITICAL} unresolved CRITICAL finding(s) remain after auto-fix.`);
    } else if (postAudit.summary.bySeverity.HIGH > 0 && verdict !== 'BLOCK') {
      verdict = 'WARN';
      reasons.push(`${postAudit.summary.bySeverity.HIGH} unresolved HIGH finding(s) remain; human sign-off required.`);
    }

    const verdictColor =
      verdict === 'BLOCK' ? chalk.bgRed.white.bold :
      verdict === 'WARN' ? chalk.yellow.bold :
      chalk.green.bold;

    console.log(`  Readiness score: ${postAudit.summary.releaseReadinessScore}/100`);
    console.log(`  Final verdict:   ${verdictColor(verdict)}`);
    if (reasons.length) {
      console.log('  Reasons:');
      reasons.forEach((r) => console.log(`    - ${r}`));
    }
    console.log('');

    const releaseReportPath = path.resolve(process.cwd(), 'bobguard-release-report.json');
    fs.writeFileSync(
      releaseReportPath,
      JSON.stringify(
        {
          tool: 'bobguard',
          version: '0.2.0',
          target: path.relative(process.cwd(), resolvedTarget).replace(/\\/g, '/'),
          generatedAt: new Date().toISOString(),
          preAudit: preAudit.summary,
          fix: fixOutcome.fixResult.summary,
          regression: fixOutcome.regression,
          postAudit: postAudit.summary,
          finalVerdict: verdict,
          reasons,
          sarifReport: sarifResult.outputPath
        },
        null,
        2
      ),
      'utf8'
    );
    console.log(chalk.cyan.bold(`Release report written -> ${releaseReportPath}\n`));

    if (verdict === 'BLOCK') {
      process.exitCode = 1;
    }
  });

// ---------------------------------------------------------------------------
// bobguard init
// ---------------------------------------------------------------------------

program
  .command('init')
  .description('Install a git pre-commit hook and VS Code task for BobGuard audits')
  .option('--workspace <dir>', 'workspace root (default: current directory)', '.')
  .option('--target <dir>', 'microservice to audit in the hook (default: ./demo-app)', './demo-app')
  .action((options) => {
    const workspaceRoot = path.resolve(process.cwd(), options.workspace);
    const auditTarget  = options.target;

    // -- Git pre-commit hook --------------------------------------------------
    const gitHooksDir = path.join(workspaceRoot, '.git', 'hooks');
    if (!fs.existsSync(gitHooksDir)) {
      console.log(chalk.yellow(`  [init] No .git/hooks directory found at ${gitHooksDir}.`));
      console.log(chalk.yellow('  [init] Make sure you are inside a Git repository root.\n'));
    } else {
      const hookPath = path.join(gitHooksDir, 'pre-commit');
      const hookScript =
        `#!/bin/sh\n` +
        `# BobGuard pre-commit security audit (installed by 'bobguard init')\n` +
        `echo "[BobGuard] Running security audit before commit..."\n` +
        `node "${path.resolve(__filename)}" audit "${auditTarget}"\n` +
        `EXIT_CODE=$?\n` +
        `if [ $EXIT_CODE -ne 0 ]; then\n` +
        `  echo "[BobGuard] Audit reported findings. Commit blocked."\n` +
        `  exit 1\n` +
        `fi\n`;
      fs.writeFileSync(hookPath, hookScript, { mode: 0o755, encoding: 'utf8' });
      console.log(chalk.green.bold(`  [init] Git pre-commit hook installed -> ${hookPath}`));
    }

    // -- VS Code tasks.json ---------------------------------------------------
    const vscodeDir = path.join(workspaceRoot, '.vscode');
    if (!fs.existsSync(vscodeDir)) {
      fs.mkdirSync(vscodeDir, { recursive: true });
    }
    const tasksPath = path.join(vscodeDir, 'tasks.json');
    const tasksJson = {
      version: '2.0.0',
      tasks: [
        {
          label: 'BobGuard: Security Scan',
          type: 'shell',
          command: `node "${path.resolve(__filename)}" audit "${auditTarget}"`,
          group: { kind: 'build', isDefault: true },
          presentation: {
            reveal: 'always',
            panel: 'shared',
            clear: true
          },
          problemMatcher: []
        },
        {
          label: 'BobGuard: Generate SBOM',
          type: 'shell',
          command: `node "${path.resolve(__filename)}" audit "${auditTarget}" --sbom bom.json`,
          group: 'build',
          presentation: { reveal: 'always', panel: 'shared' },
          problemMatcher: []
        },
        {
          label: 'BobGuard: Compliance Attestation',
          type: 'shell',
          command: `node "${path.resolve(__filename)}" audit "${auditTarget}" --attestation compliance-matrix.md`,
          group: 'build',
          presentation: { reveal: 'always', panel: 'shared' },
          problemMatcher: []
        }
      ]
    };
    fs.writeFileSync(tasksPath, JSON.stringify(tasksJson, null, 2), 'utf8');
    console.log(chalk.green.bold(`  [init] VS Code tasks.json written    -> ${tasksPath}\n`));
    console.log(chalk.cyan('  Tasks available in VS Code (Ctrl+Shift+B):'));
    console.log(chalk.cyan('    • BobGuard: Security Scan'));
    console.log(chalk.cyan('    • BobGuard: Generate SBOM'));
    console.log(chalk.cyan('    • BobGuard: Compliance Attestation\n'));
  });

// ---------------------------------------------------------------------------
// bobguard fix --interactive helper
// ---------------------------------------------------------------------------

/**
 * Interactive fix mode: shows each pending patch with a diff preview and
 * prompts for Y/n confirmation before writing to disk.
 * Uses readline for synchronous-style prompting without external deps.
 * @param {string} targetDir
 */
function runFixInteractive(targetDir) {
  const resolvedTarget = path.resolve(process.cwd(), targetDir);
  if (!fs.existsSync(resolvedTarget)) {
    console.error(chalk.red(`Target directory not found: ${resolvedTarget}`));
    process.exitCode = 1;
    return;
  }

  // We need the individual fix functions, not the combined runner, so we can
  // preview diffs per-fixer before writing.
  const {
    fixSqlInjection, fixMassAssignment, generateUnifiedDiff,
    fixWeakCrypto, fixInsecureTimeout, fixLogSensitive, fixDependencies
  } = require('../lib/fixer');

  console.log(chalk.magenta.bold(`\nBobGuard interactive fix -> ${resolvedTarget}\n`));

  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  /** Prompt helper that returns a Promise resolving to the trimmed answer. */
  function prompt(question) {
    return new Promise((resolve) => rl.question(question, (ans) => resolve(ans.trim())));
  }

  /**
   * Preview + optionally apply an in-memory fixer (returns {content, changed, notes}).
   * @param {string} label   human-readable patch name
   * @param {string} filePath  absolute path to file
   * @param {Function} fixerFn  (content) => {content, changed, notes}
   */
  async function reviewInMemoryFix(label, filePath, fixerFn) {
    if (!fs.existsSync(filePath)) return;
    const original = fs.readFileSync(filePath, 'utf8');
    const result = fixerFn(original);
    if (!result.changed) return;

    const relLabel = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
    console.log(chalk.bold(`\n[${label}] ${relLabel}`));
    result.notes.forEach((n) => console.log(chalk.gray(`  - ${n}`)));
    console.log(chalk.gray(generateUnifiedDiff(original, result.content, relLabel)));

    const ans = await prompt(chalk.yellow('Apply this fix? [Y/n] '));
    if (ans === '' || ans.toLowerCase() === 'y') {
      fs.writeFileSync(filePath, result.content, 'utf8');
      console.log(chalk.green('  ✔ Applied.'));
    } else {
      console.log(chalk.gray('  Skipped.'));
    }
  }

  /**
   * Preview + optionally apply a directory-walker fixer (returns result[]).
   * @param {string} label
   * @param {Function} dirFixerFn  (targetDir) => [{filePath, applied, notes, diff}]
   */
  async function reviewDirFix(label, dirFixerFn) {
    const results = dirFixerFn(resolvedTarget);
    const applicable = results.filter((r) => r.applied || r.notes.length > 0);
    if (applicable.length === 0) return;

    for (const r of applicable) {
      if (!r.applied) continue;
      const relLabel = path.relative(process.cwd(), r.filePath).replace(/\\/g, '/');
      console.log(chalk.bold(`\n[${label}] ${relLabel}`));
      r.notes.forEach((n) => console.log(chalk.gray(`  - ${n}`)));
      // diff was already generated against the original; we need to regenerate
      // to show because the file was already written (dir fixers write on detect).
      // Re-read and re-apply to show diff without writing twice: just show existing diff.
      console.log(chalk.gray(r.diff || '(diff not available)'));

      const ans = await prompt(chalk.yellow('This change was already applied. Accept? [Y/n] '));
      if (ans.toLowerCase() === 'n') {
        // Revert: the fixer already wrote; read the original from diff header isn't easy.
        // We inform the user to use git checkout.
        console.log(chalk.yellow('  Revert with: git checkout -- ' + relLabel));
      } else {
        console.log(chalk.green('  ✔ Accepted.'));
      }
    }
  }

  (async () => {
    try {
      const serverJs = path.join(resolvedTarget, 'server.js');
      await reviewInMemoryFix('SQL Injection fix', serverJs, fixSqlInjection);
      await reviewInMemoryFix('Mass Assignment fix', serverJs, fixMassAssignment);
      await reviewDirFix('Weak Crypto fix', fixWeakCrypto);
      await reviewDirFix('Insecure Timeout fix', fixInsecureTimeout);
      await reviewDirFix('Log Sensitive fix', fixLogSensitive);

      console.log(chalk.bold('\n  Running post-fix test suite...'));
      const { runTestSuite: rts } = require('../lib/runner');
      const afterTests = rts(resolvedTarget);
      if (!afterTests.ran) {
        console.log(chalk.yellow(`  skipped: ${afterTests.error}`));
      } else {
        console.log(`  ${afterTests.passed ? chalk.green('PASS') : chalk.red('FAIL')} ` +
          `(${afterTests.metrics.numPassedTests}/${afterTests.metrics.numTotalTests} tests)\n`);
      }
    } finally {
      rl.close();
    }
  })();
}

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}