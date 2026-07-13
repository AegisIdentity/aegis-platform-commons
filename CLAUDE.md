# aegis-platform-commons — working notes

Five shared libraries. Java 21 / Spring Boot 4.1. Root package `io.aegis.commons.*`.

## Sharing rule
Shared **code**, never a shared **database** (ADR-0002). Applying the same hardening everywhere is
the point of `aegis-security-commons`; a shared DB would break tenant isolation and coupling.

## Non-negotiables
- `TenantContext` **must** be cleared in a finally block (pooled-thread reuse ⇒ cross-tenant leak).
  `TenantContextFilter` does this; new code paths must too.
- `SecurityHardening` is the single definition of the hardening baseline — change it here, not per
  service. `CorsConfigFactory` refuses wildcard-origin-with-credentials; keep it that way.
- Audit events must never carry secrets (passwords, tokens, full assertions).

## Build / test
`mvn install`. Tests are fast unit tests (no containers). Keep them that way — integration coverage
lives in the services.
