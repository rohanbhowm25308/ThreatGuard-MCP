# ThreatGuard MCP — Self Security Review

## Scope and assets
The project offers a read-only Python MCP server (stdio) and a separate local Flask dashboard API. The sole upstream data source is the public CISA KEV JSON feed. Assets: host availability, local log integrity, accuracy of displayed intelligence, and the MCP client trust boundary. The project does not store credentials or private user data.

## Threat model
- Malicious clients may send invalid CVE IDs, oversized search queries, or flood requests.
- An upstream response may be malformed, unavailable, unexpectedly large, or contain instruction-like text.
- A remote deployment without authentication could expose the dashboard API to untrusted clients.
- A malicious or compromised MCP client may invoke tools excessively; the MCP stdio entrypoint has a process-wide limiter, not a per-client authenticated limiter.

## Implemented controls
1. **Read-only:** MCP exports only `get_latest_vulnerabilities`, `get_vulnerability`, `search_vulnerabilities`, and `get_catalog_stats`; Flask API only supports GET endpoints. Neither modifies the upstream catalog.
2. **Validation:** CVE regex, bounded query length, printable-character validation, and maximum result count 100; browser displays data via `textContent` to avoid HTML injection.
3. **Web API rate limit:** In-memory per-remote-address sliding window, 30 requests per 60 seconds, returns HTTP 429. This is a **single-process demonstration control**, not distributed production protection.
4. **Logging:** Invalid input, web rate-limit events, unexpected errors, and MCP tool invocation metadata are logged. Search queries are not logged by Flask. Do not log secrets or complete vulnerability payloads.
5. **Network:** CISA feed URL is hardcoded (not user-controlled), redirects disabled, TLS verified, bounded timeouts, response size checked after retrieval, and JSON shape validated.
6. **Headers:** Content Security Policy, `nosniff`, clickjacking prevention, referrer policy, and no-store caching. No external script or CSS dependencies.
7. **Failure handling:** Upstream failures produce a 503 unless a previous cached copy exists; stale fallback is possible and should be identified in a production UI.

## Test evidence
Run `python -m pytest -q`. Automated tests check input rejection, rate limiting, GET-only behavior, security headers, and basic search. These are local tests using mocked catalog data, not a penetration test.

## Findings and residual risks
| Risk | Severity | Status / recommendation |
|---|---|---|
| Unauthenticated public API | High if Internet-exposed | Keep bound to localhost; add authentication, HTTPS and proxy policy before public deployment. |
| MCP tool call flooding | Medium | **Partially mitigated:** stdio MCP tools enforce 30 calls/min per process; use authenticated per-client quotas for multi-client production servers. |
| Multi-worker bypass of web limiter | Medium | **Open:** use Redis or a gateway-based distributed rate limiter in production. |
| Cache staleness | Low/Medium | Cached data may lag; show cache age and enforce a maximum stale duration for production. |
| Upstream payload memory use | Medium | Content length checked after download; add streaming byte limits for stronger protection. |
| Log retention and tampering | Medium | Console logs are not durable; configure centralized logging, retention, permissions and monitoring. |
| Trusting upstream text as AI instructions | Medium | MCP description warns clients; client must treat retrieved strings strictly as untrusted data. |
| Lack of full security integration tests | Medium | Add negative MCP client tests, load tests, upstream schema fixtures and deployment security checks. |

## Security conclusion
Suitable as a local educational prototype and demonstration, **not production hardened**. The most important next steps are per-client MCP rate limiting, authentication for network deployments, centralized logging, streaming size limits and distributed throttling. CISA KEV membership is not a comprehensive vulnerability or exploitability assessment; absence from KEV does not mean safe.


## Larger CSV preview uploads
The local preview permits at most 25 MiB and 20,000 rows. These caps mitigate memory exhaustion, but a malicious authenticated/untrusted uploader could still consume significant memory or CPU. Keep the app local or add authentication, per-user quotas, streaming parsing, and paginated responses before public deployment.
