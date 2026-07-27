# flask-audit-lab

A worked security audit, start to finish. One small Flask API in two builds, a
full report, and a test suite where every finding is a working exploit.

I wrote this as a sample of how I do code review. Rather than describe a
methodology, it shows the whole output of one: the target, the report, the
fixes, and the proof that the fixes hold.

## What is here

| Path | What it is |
|------|-----------|
| `AUDIT.md` | The audit report. Nine findings, OWASP mapped, with severity, proof, impact and remediation. |
| `vulnerable/app.py` | The audit target. Nine deliberate flaws. Do not deploy. |
| `hardened/app.py` | Same API, same layout, all nine closed. |
| `openapi.yaml` | OpenAPI 3.0 spec for the hardened build. |
| `tests/test_exploits.py` | A working exploit per finding, fired at both builds. |
| `tests/test_api_parity.py` | The same legitimate workflows against both builds. |
| `tests/test_openapi_contract.py` | Checks the spec against the code. |

The two apps keep the same file layout and route order, so `diff` is a useful
way to read the fixes:

```bash
diff -u vulnerable/app.py hardened/app.py
```

## Running it

```bash
pip install -r requirements.txt
pytest tests/ -v
```

95 tests, no network, no fixtures to set up. Each test builds its own SQLite
database in a temp directory.

## Findings

| ID | Finding | OWASP | Severity |
|----|---------|-------|----------|
| F-01 | SQL injection in expense search | A03 Injection | Critical |
| F-02 | IDOR: any expense readable by id | A01 Broken Access Control | Critical |
| F-04 | Session token derived from public data | A07 Auth Failures | Critical |
| F-03 | Unsalted MD5 password storage | A02 Cryptographic Failures | High |
| F-07 | Mass assignment on expense creation | A08 Data Integrity Failures | High |
| F-06 | No login rate limiting | A04 Insecure Design | Medium |
| F-05 | Traceback disclosure and debug mode | A05 Misconfiguration | Medium |
| F-08 | Session token written to logs | A09 Logging Failures | Medium |
| F-09 | Username enumeration on login | A07 Auth Failures | Low |

Full detail, including proof of concept and remediation for each, is in
[AUDIT.md](AUDIT.md).

## How the tests prove anything

The rule I follow is that a finding I cannot exploit does not go in the report.
Every finding here has a test that carries out the attack against
`vulnerable/app.py` and asserts it succeeds, plus a test that runs the identical
attack against `hardened/app.py` and asserts it fails.

F-04 is the clearest example. The test never reads the victim's session token.
It takes the username, which is public, and a rough login time, brute forces the
eleven candidate seconds, and recovers a token that matches the real one exactly.
Against the hardened build the same code finds nothing.

The parity tests matter just as much. A fix that breaks the product is not a
fix, so all 18 run against both builds and assert identical behaviour.

## Known limitations

Stated plainly, because an audit that hides its own gaps is not worth much.

- **The rate limit is in process memory.** It resets on restart and does not
  work across multiple workers. Production needs shared storage such as Redis.
  It is keyed on username only, so it does not stop a spray across many
  accounts, and it does allow deliberate lockout of a known username.
- **No token revocation.** Sessions are concurrent and expire on a one hour TTL.
  There is no logout endpoint, so a stolen token stays valid until it expires.
- **Application code only.** No TLS, CORS, hosting, dependency or secrets review.
- **No CSRF protection**, which is correct for a pure bearer token API and would
  not be if cookie auth were added later.
- **SQLite and a single process.** Concurrency and race conditions are out of
  scope, and this would not survive production load as written.
- **The audit is manual.** No third party scanner was run. Findings come from
  reading the code, and each is backed by an exploit rather than a tool's
  confidence score.

## A note on the vulnerable build

`vulnerable/app.py` is a teaching target of the same kind as WebGoat or DVWA.
Every flaw in it is common, documented, and paired here with its fix. It binds
to localhost, ships no data, and exists so the hardened build has something to
be measured against. Do not deploy it.

## Licence

MIT. See [LICENSE](LICENSE).
