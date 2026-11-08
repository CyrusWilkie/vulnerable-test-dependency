"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.TEST_ONLY_NOTICE = void 0;
exports.evaluateExpression = evaluateExpression;
exports.buildFunction = buildFunction;
exports.parseConfig = parseConfig;
exports.pingHost = pingHost;
exports.listDirectory = listDirectory;
exports.readUserFile = readUserFile;
exports.readTemplate = readTemplate;
exports.saveUpload = saveUpload;
exports.buildUserLookupQuery = buildUserLookupQuery;
exports.findUserByName = findUserByName;
exports.searchProducts = searchProducts;
exports.authenticate = authenticate;
const child_process_1 = require("child_process");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
exports.TEST_ONLY_NOTICE = "vulnerable-test-dependency: intentionally insecure code for scanner validation. Do not use in production.";
// ---------------------------------------------------------------------------
// 1. Unsafe eval / dynamic code execution  (CWE-95)
// ---------------------------------------------------------------------------
/** VULNERABLE (CWE-95): evaluates a caller-supplied expression with eval(). */
function evaluateExpression(expression) {
    // eslint-disable-next-line no-eval
    return eval(expression);
}
/** VULNERABLE (CWE-95): builds a function from caller-supplied source via the Function constructor. */
function buildFunction(body) {
    // eslint-disable-next-line no-new-func
    return new Function("...args", body);
}
/** VULNERABLE (CWE-95): "parses" JSON-ish input using eval instead of JSON.parse. */
function parseConfig(raw) {
    // eslint-disable-next-line no-eval
    return eval("(" + raw + ")");
}
// ---------------------------------------------------------------------------
// 2. OS command injection  (CWE-78)
// ---------------------------------------------------------------------------
/** VULNERABLE (CWE-78): user-controlled host concatenated into a shell command. */
function pingHost(host) {
    return new Promise((resolve, reject) => {
        (0, child_process_1.exec)("ping -c 1 " + host, (err, stdout) => {
            if (err)
                return reject(err);
            resolve(stdout);
        });
    });
}
/** VULNERABLE (CWE-78): user-controlled filename interpolated into a synchronous shell command. */
function listDirectory(dir) {
    return (0, child_process_1.execSync)(`ls -la ${dir}`).toString();
}
// ---------------------------------------------------------------------------
// 3. Path traversal  (CWE-22)
// ---------------------------------------------------------------------------
const UPLOAD_ROOT = "/var/app/uploads";
/** VULNERABLE (CWE-22): joins user input onto a base dir with no normalization/containment check. */
function readUserFile(filename, baseDir = UPLOAD_ROOT) {
    const fullPath = path.join(baseDir, filename);
    return fs.readFileSync(fullPath, "utf8");
}
/** VULNERABLE (CWE-22): string-concatenated path built from user input. */
function readTemplate(name) {
    return fs.readFileSync(__dirname + "/templates/" + name, "utf8");
}
/** VULNERABLE (CWE-22 / CWE-73): writes caller-supplied content to a caller-controlled path. */
function saveUpload(filename, contents, baseDir = UPLOAD_ROOT) {
    const target = path.join(baseDir, filename);
    fs.writeFileSync(target, contents);
    return target;
}
/** VULNERABLE (CWE-89): builds a SQL string by concatenating user input. */
function buildUserLookupQuery(username) {
    return "SELECT * FROM users WHERE username = '" + username + "'";
}
/** VULNERABLE (CWE-89): executes a concatenated query through the supplied executor. */
function findUserByName(db, username) {
    const sql = "SELECT id, username, email FROM users WHERE username = '" + username + "'";
    return db.query(sql);
}
/** VULNERABLE (CWE-89): template-literal SQL with user-controlled ORDER BY and LIMIT. */
function searchProducts(db, term, sortColumn, limit) {
    return db.query(`SELECT * FROM products WHERE name LIKE '%${term}%' ORDER BY ${sortColumn} LIMIT ${limit}`);
}
/** VULNERABLE (CWE-89): login check that is bypassable with `' OR '1'='1`. */
function authenticate(db, user, pass) {
    const sql = `SELECT * FROM accounts WHERE user = '${user}' AND password = '${pass}'`;
    return db.query(sql);
}
