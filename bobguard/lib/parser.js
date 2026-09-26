'use strict';

/**
 * Thin, defensive wrapper around @babel/parser. This module owns exactly
 * one job: turn source text into an AST (or fail safely). Scope/binding
 * resolution is NOT reimplemented here - @babel/traverse's NodePath.scope
 * already provides a real, correct scope chain / symbol table, and
 * taintEngine.js consumes that directly rather than us hand-rolling a
 * second one.
 */

const parser = require('@babel/parser');
const path = require('path');

/**
 * Picks parser plugins based on file extension. TypeScript and Flow are
 * mutually exclusive in @babel/parser, so we branch on extension rather
 * than enabling both.
 * @param {string} filePath
 * @returns {string[]} plugin names for @babel/parser
 */
function getPluginsForFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const common = [
    'jsx',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'objectRestSpread',
    'optionalChaining',
    'nullishCoalescingOperator',
    'dynamicImport',
    'topLevelAwait'
  ];

  if (ext === '.ts' || ext === '.tsx') {
    return [...common.filter((p) => p !== 'jsx' || ext === '.tsx'), 'typescript'];
  }
  return common;
}

/**
 * Parses source text into a Babel AST. Never throws - on a syntax error
 * (or any parser exception) it returns { ast: null, error: <message> } so
 * callers can fall back to a non-AST analysis path for that one file
 * instead of aborting the whole scan.
 * @param {string} code
 * @param {string} filePath - used only to choose parser plugins + for error context
 * @returns {{ast: object|null, error: string|null}}
 */
function parseSource(code, filePath) {
  try {
    const ast = parser.parse(code, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      errorRecovery: true,
      plugins: getPluginsForFile(filePath)
    });
    return { ast, error: null };
  } catch (err) {
    return { ast: null, error: `${filePath}: ${err.message}` };
  }
}

module.exports = {
  parseSource,
  getPluginsForFile
};
