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

## Agent identity (added 2026-08-26)
`aegis-agent-commons` is **protocol-agnostic on purpose** (ADR-0011). MCP / A2A / AP2 field names
appear only under `io.aegis.commons.agent.protocol`. If a protocol type leaks into the core model,
the next protocol revision becomes a platform-wide change instead of an adapter change.

Two rules that are load-bearing rather than stylistic:
- **Unknown fields fail closed.** `McpToolAdapter` uses a deny-list of cosmetic fields, so an
  unrecognized field counts as semantic and forces re-consent. An allow-list would fail open on
  exactly the case that matters (a new field that instructs the model).
- **Unverified assertions confer nothing.** An A2A card with an unverified signature parses and is
  recorded, but `effectiveSkills()` returns empty. Record the claim, act on none of it.
- **A2A signatures are really verified** (`A2aCardVerifier`), not asserted by the caller. The signed
  payload is the card *minus* its `signatures` field, canonicalized — so signer and verifier must
  canonicalize identically or a valid signature reads as tampering. That interop hazard is inherent
  to embedding signatures in the signed document; start there if a partner's cards fail.

## Vault (added 2026-08-26)
`aegis-vault-commons` — ADR-0015/0016. Two rules:
- **`TenantVaultPaths` has no overload taking a tenant argument, and must never gain one.** The
  tenant segment is derived from `TenantContext`, exactly like `X-Aegis-Tenant` at the edge. A
  tenant-supplied path string must never reach Vault.
- **Transit keys are created with `exportable=false`.** A key that can be exported defeats the
  reason for using Transit at all, so it is not a caller-tunable option.

Built on a narrow `VaultClient` SPI, not a Vault SDK — keeps these tests container-free, keeps the
dependency/CVE surface small on a component that now sits on the token path, and makes the path
templating testable in isolation.
