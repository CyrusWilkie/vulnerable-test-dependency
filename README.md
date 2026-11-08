# vulnerable-test-dependency

> **⚠️ TEST ONLY — INTENTIONALLY INSECURE CODE. DO NOT USE IN PRODUCTION.**

A minimal TypeScript library that contains deliberate, well-known vulnerability
patterns. Use it to check that SAST and SCA tools detect what
they should.

- No runtime dependencies.
- No `install`/`postinstall` lifecycle scripts.
- Nothing runs on import. Each vulnerable path only runs when you call the exported function.

## Vulnerability catalogue

| Export | Pattern | CWE |
| --- | --- | --- |
| `evaluateExpression`, `parseConfig` | `eval()` on input | CWE-95 |
| `buildFunction` | `new Function()` on input | CWE-95 |
| `pingHost` | `exec()` with concatenated input | CWE-78 |
| `listDirectory` | `execSync()` with interpolated input | CWE-78 |
| `readUserFile`, `readTemplate` | Unchecked path join / concat on read | CWE-22 |
| `saveUpload` | Unchecked path on write | CWE-22 / CWE-73 |
| `buildUserLookupQuery`, `findUserByName`, `authenticate` | String-concatenated SQL | CWE-89 |
| `searchProducts` | Template-literal SQL, injectable `ORDER BY` / `LIMIT` | CWE-89 |

SQL functions take a caller-supplied `QueryExecutor` (`{ query(sql): Promise }`),
so the package doesn't need a database driver.

## Build

```sh
npm install
npm run build      # outputs dist/index.js + dist/index.d.ts
```
