# aegis-platform-commons

Shared libraries consumed by every Aegis service (multi-module):

| Module | What |
|---|---|
| `aegis-tenant-context` | `TenantId` value type, request-scoped tenant holder, propagation filter |
| `aegis-web-commons` | correlation-id filter, safe RFC-7807 (ProblemDetail) error model |
| `aegis-audit-commons` | audit event model + publisher SPI + structured-logging publisher |
| `aegis-agent-commons` | protocol-agnostic AI-agent identity: agent principals with a mandatory owner edge, content-addressed tool identity, bounded mandates; MCP / A2A / AP2 adapters |
| `aegis-security-commons` | hardening headers/CSP, stateless-bearer-API defaults, CORS, auth-event→audit bridge, auto-config |
| `aegis-testing-support` | Testcontainers `@ServiceConnection` config + `jwt()` MockMvc helpers |

## Build
```bash
mvn install   # after aegis-platform-bom; installs all five jars to ~/.m2
```
41 unit tests cover the tenant/web/audit/security logic.
