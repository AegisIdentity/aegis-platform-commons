package io.aegis.commons.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * @param token     inline static token. Avoid: an inline token leaks into {@code docker inspect},
 *                  process listings and crash dumps. Prefer {@code tokenFile}.
 * @param tokenFile path to a file containing the token. This is the normal production shape —
 *                  Kubernetes projects secrets as files and the Vault Agent writes its renewed token
 *                  to a sink file — so it takes precedence over {@code token}.
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
        String tokenFile,
        Duration timeout) {

    /**
     * The token to present, preferring {@code tokenFile}.
     *
     * @throws VaultException if a token file is configured but unreadable. Falling back to the inline
     *                        token there would mask a misconfigured secret mount and run with the
     *                        wrong identity, which is worse than refusing to start.
     */
    public String resolvedToken() {
        if (tokenFile != null && !tokenFile.isBlank()) {
            try {
                // Trimmed: a token written by a shell redirect carries a trailing newline, and Vault
                // answers a bare 403 that says nothing about why.
                return Files.readString(Path.of(tokenFile)).trim();
            } catch (IOException e) {
                throw new VaultException("cannot read vault token file: " + tokenFile, e);
            }
        }
        return (token == null || token.isBlank()) ? null : token;
    }

    public VaultProperties {
        uri = uri == null ? "http://localhost:8200" : uri;
        isolation = isolation == null ? VaultIsolation.PATH : isolation;
        mount = mount == null ? "aegis" : mount;
        timeout = timeout == null ? Duration.ofSeconds(3) : timeout;
    }
}
