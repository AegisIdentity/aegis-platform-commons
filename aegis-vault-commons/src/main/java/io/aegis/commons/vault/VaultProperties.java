package io.aegis.commons.vault;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Vault configuration. See {@code VAULT-ARCHITECTURE.md} §6.3.
 *
 * @param enabled   master switch; when false no Vault beans are created and services fall back to
 *                  their existing key source (used during the ADR-0007 → ADR-0015 migration)
 * @param uri       Vault address, e.g. {@code https://vault.aegis.svc:8200}
 * @param isolation PATH for Vault OSS, NAMESPACE for Enterprise
 * @param mount     root mount, {@code aegis} by default
 * @param token     static token — <b>development only</b>; production uses Kubernetes or AppRole auth
 * @param timeout   per-request timeout; Vault is on the token path, so this must be short enough
 *                  that a Vault stall cannot exhaust the request threads of every service
 */
@ConfigurationProperties(prefix = "aegis.vault")
public record VaultProperties(
        boolean enabled,
        String uri,
        VaultIsolation isolation,
        String mount,
        String token,
        Duration timeout) {

    public VaultProperties {
        uri = uri == null ? "http://localhost:8200" : uri;
        isolation = isolation == null ? VaultIsolation.PATH : isolation;
        mount = mount == null ? "aegis" : mount;
        timeout = timeout == null ? Duration.ofSeconds(3) : timeout;
    }
}
