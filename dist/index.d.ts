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
export declare const TEST_ONLY_NOTICE = "vulnerable-test-dependency: intentionally insecure code for scanner validation. Do not use in production.";
/** VULNERABLE (CWE-95): evaluates a caller-supplied expression with eval(). */
export declare function evaluateExpression(expression: string): unknown;
/** VULNERABLE (CWE-95): builds a function from caller-supplied source via the Function constructor. */
export declare function buildFunction(body: string): (...args: unknown[]) => unknown;
/** VULNERABLE (CWE-95): "parses" JSON-ish input using eval instead of JSON.parse. */
export declare function parseConfig(raw: string): unknown;
/** VULNERABLE (CWE-78): user-controlled host concatenated into a shell command. */
export declare function pingHost(host: string): Promise<string>;
/** VULNERABLE (CWE-78): user-controlled filename interpolated into a synchronous shell command. */
export declare function listDirectory(dir: string): string;
/** VULNERABLE (CWE-22): joins user input onto a base dir with no normalization/containment check. */
export declare function readUserFile(filename: string, baseDir?: string): string;
/** VULNERABLE (CWE-22): string-concatenated path built from user input. */
export declare function readTemplate(name: string): string;
/** VULNERABLE (CWE-22 / CWE-73): writes caller-supplied content to a caller-controlled path. */
export declare function saveUpload(filename: string, contents: string, baseDir?: string): string;
/**
 * Minimal driver-agnostic query interface so this package has no DB
 * dependency. Compatible in shape with `pg`, `mysql2`, `sqlite`, etc.
 */
export interface QueryExecutor {
    query(sql: string): Promise<unknown>;
}
/** VULNERABLE (CWE-89): builds a SQL string by concatenating user input. */
export declare function buildUserLookupQuery(username: string): string;
/** VULNERABLE (CWE-89): executes a concatenated query through the supplied executor. */
export declare function findUserByName(db: QueryExecutor, username: string): Promise<unknown>;
/** VULNERABLE (CWE-89): template-literal SQL with user-controlled ORDER BY and LIMIT. */
export declare function searchProducts(db: QueryExecutor, term: string, sortColumn: string, limit: string): Promise<unknown>;
/** VULNERABLE (CWE-89): login check that is bypassable with `' OR '1'='1`. */
export declare function authenticate(db: QueryExecutor, user: string, pass: string): Promise<unknown>;
