package io.aegis.commons.vault;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Vault KV v2 secrets, tenant-scoped.
 *
 * <p>KV v2 is asymmetric in a way that catches people out: a <b>read</b> returns
 * {@code {"data": {"data": {...}, "metadata": {...}}}} — a double envelope — while a <b>write</b>
 * takes {@code {"data": {...}}}, a single one. Getting it wrong yields nulls rather than an error,
 * so the asymmetry is handled here once and covered by tests.
 */
public class VaultSecrets {

    private final VaultClient client;
    private final TenantVaultPaths paths;

    public VaultSecrets(VaultClient client, TenantVaultPaths paths) {
        this.client = client;
        this.paths = paths;
    }

    /** One field of a secret, or empty if either the secret or the field is absent. */
    public Optional<String> get(String path, String key) {
        return Optional.ofNullable(getAll(path).get(key));
    }

    /** Every field of a secret; empty map when the secret does not exist. */
    public Map<String, String> getAll(String path) {
        Map<String, Object> inner = unwrap(client.read(paths.kv(path), paths.namespace()));
        Map<String, String> result = new LinkedHashMap<>();
        inner.forEach((k, v) -> {
            if (v != null) {
                result.put(k, String.valueOf(v));
            }
        });
        return result;
    }

    public void put(String path, Map<String, String> values) {
        client.write(paths.kv(path), Map.of("data", values), paths.namespace());
    }

    public void delete(String path) {
        client.delete(paths.kv(path), paths.namespace());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> unwrap(Map<String, Object> response) {
        Object outer = response == null ? null : response.get("data");
        if (!(outer instanceof Map<?, ?> outerMap)) {
            return Map.of();
        }
        Object inner = outerMap.get("data");
        return inner instanceof Map<?, ?> innerMap ? (Map<String, Object>) innerMap : Map.of();
    }
}
