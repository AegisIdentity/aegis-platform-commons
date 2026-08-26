package io.aegis.commons.vault;

import java.util.Map;

/**
 * The narrow HTTP surface this platform uses against Vault.
 *
 * <p>Deliberately an SPI rather than a Vault SDK dependency. The surface we need is three verbs; the
 * seam keeps {@code aegis-vault-commons} unit tests container-free (this repo's testing rule), and
 * it makes the security-critical path templating in {@link TenantVaultPaths} testable in isolation
 * from any transport concern.
 *
 * <p>Implementations must not log request or response bodies — both routinely contain key material.
 *
 * @see RestClientVaultClient the production implementation
 */
public interface VaultClient {

    /** GET a path. Returns an empty map when the path does not exist. */
    Map<String, Object> read(String path, String namespace);

    /** POST a path. Returns the response body, or an empty map if there is none. */
    Map<String, Object> write(String path, Map<String, Object> data, String namespace);

    /** DELETE a path. */
    void delete(String path, String namespace);
}
