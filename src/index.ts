/**
 * ============================================================================
 *  WARNING: TEST ONLY — INTENTIONALLY INSECURE CODE
 * ============================================================================
 *  This module exists solely to validate SAST / SCA tools.
 *  Every exported function contains a deliberate, well-known vulnerability
 *  pattern. Nothing in this file executes on import or install; each function
 *  only runs if a caller explicitly invokes it.
 *
 *  DO NOT use this package in production or expose it to untrusted input.
 * ============================================================================
 */

import { exec, execFile, execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

export const TEST_ONLY_NOTICE =
  "vulnerable-test-dependency: intentionally insecure code for scanner validation. Do not use in production.";

// ---------------------------------------------------------------------------
// 1. Unsafe eval / dynamic code execution  (CWE-95)
// ---------------------------------------------------------------------------

/** VULNERABLE (CWE-95): evaluates a caller-supplied expression with eval(). */
export function evaluateExpression(expression: string): unknown {
  // eslint-disable-next-line no-eval
  return eval(expression);
}

/** VULNERABLE (CWE-95): builds a function from caller-supplied source via the Function constructor. */
export function buildFunction(body: string): (...args: unknown[]) => unknown {
  // eslint-disable-next-line no-new-func
  return new Function("...args", body) as (...args: unknown[]) => unknown;
}

/** VULNERABLE (CWE-95): "parses" JSON-ish input using eval instead of JSON.parse. */
export function parseConfig(raw: string): unknown {
  // eslint-disable-next-line no-eval
  return eval("(" + raw + ")");
}

// ---------------------------------------------------------------------------
// 2. OS command injection  (CWE-78)
// ---------------------------------------------------------------------------

/** VULNERABLE (CWE-78): user-controlled host concatenated into a shell command. */
export function pingHost(host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    exec("ping -c 1 " + host, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

/** VULNERABLE (CWE-78): user-controlled filename interpolated into a synchronous shell command. */
export function listDirectory(dir: string): string {
  return execSync(`ls -la ${dir}`).toString();
}

// The two functions below use execFile (no shell), so they also work in
// shell-less / distroless containers where exec()/execSync() fail with ENOENT.

/** Promise wrapper around execFile. Not itself vulnerable; the callers below are. */
function execFileAsync(file: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

/**
 * VULNERABLE (CWE-78): caller controls both the executable and its arguments.
 * No shell is involved, but any binary present in the container can be run.
 */
export function runCommand(command: string, args: string[] = []): Promise<string> {
  return execFileAsync(command, args);
}

/**
 * VULNERABLE (CWE-88, argument injection): meant to report Node runtime info
 * (e.g. "--version"), but a caller-supplied option goes straight onto the
 * node command line. Passing "--eval=<code>" runs arbitrary JavaScript. The
 * node binary is always present, so this is exploitable even on distroless.
 */
export function getNodeInfo(flag: string): Promise<string> {
  return execFileAsync(process.execPath, [flag]);
}

// ---------------------------------------------------------------------------
// 3. Path traversal  (CWE-22)
// ---------------------------------------------------------------------------

const UPLOAD_ROOT = "/var/app/uploads";

/** VULNERABLE (CWE-22): joins user input onto a base dir with no normalization/containment check. */
export function readUserFile(filename: string, baseDir: string = UPLOAD_ROOT): string {
  const fullPath = path.join(baseDir, filename);
  return fs.readFileSync(fullPath, "utf8");
}

/** VULNERABLE (CWE-22): string-concatenated path built from user input. */
export function readTemplate(name: string): string {
  return fs.readFileSync(__dirname + "/templates/" + name, "utf8");
}

/** VULNERABLE (CWE-22 / CWE-73): writes caller-supplied content to a caller-controlled path. */
export function saveUpload(filename: string, contents: string, baseDir: string = UPLOAD_ROOT): string {
  const target = path.join(baseDir, filename);
  fs.writeFileSync(target, contents);
  return target;
}

// ---------------------------------------------------------------------------
// 4. SQL injection  (CWE-89)
// ---------------------------------------------------------------------------

/**
 * Minimal driver-agnostic query interface so this package has no DB
 * dependency. Compatible in shape with `pg`, `mysql2`, `sqlite`, etc.
 */
export interface QueryExecutor {
  query(sql: string): Promise<unknown>;
}

/** VULNERABLE (CWE-89): builds a SQL string by concatenating user input. */
export function buildUserLookupQuery(username: string): string {
  return "SELECT * FROM users WHERE username = '" + username + "'";
}

/** VULNERABLE (CWE-89): executes a concatenated query through the supplied executor. */
export function findUserByName(db: QueryExecutor, username: string): Promise<unknown> {
  const sql = "SELECT id, username, email FROM users WHERE username = '" + username + "'";
  return db.query(sql);
}

/** VULNERABLE (CWE-89): template-literal SQL with user-controlled ORDER BY and LIMIT. */
export function searchProducts(
  db: QueryExecutor,
  term: string,
  sortColumn: string,
  limit: string
): Promise<unknown> {
  return db.query(
    `SELECT * FROM products WHERE name LIKE '%${term}%' ORDER BY ${sortColumn} LIMIT ${limit}`
  );
}

/** VULNERABLE (CWE-89): login check that is bypassable with `' OR '1'='1`. */
export function authenticate(db: QueryExecutor, user: string, pass: string): Promise<unknown> {
  const sql = `SELECT * FROM accounts WHERE user = '${user}' AND password = '${pass}'`;
  return db.query(sql);
}
