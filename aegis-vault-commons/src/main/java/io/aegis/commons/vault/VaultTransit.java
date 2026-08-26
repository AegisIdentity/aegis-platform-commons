package io.aegis.commons.vault;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Vault Transit — key generation, signing, verification, encryption and rotation.
 *
 * <p><b>The private key never leaves Vault.</b> This class sends bytes to be signed and receives a
 * signature; it never holds key material. That is a strict improvement on the KMS envelope scheme it
 * replaces (ADR-0007), where the private key was unwrapped into application memory and cached — a
 * memory-disclosure bug in a Spring service can no longer yield a tenant's signing key, because the
 * key was never in the process.
 *
 * <p>Every operation emits an audit event carrying the <em>key name and operation</em> and never the
 * signature, ciphertext, plaintext or any key material, per the platform's standing rule that audit
 * events must not contain secrets.
 */
public class VaultTransit {

    private final VaultClient client;
    private final TenantVaultPaths paths;
    private final AuditEventPublisher audit;

    public VaultTransit(VaultClient client, TenantVaultPaths paths, AuditEventPublisher audit) {
        this.client = client;
        this.paths = paths;
        this.audit = audit;
    }

    /**
     * Create a key. {@code exportable} and {@code allow_plaintext_backup} are pinned to
     * {@code false}: a key that can be exported defeats the entire reason for using Transit, so it
     * is not a caller-tunable option.
     */
    public void createKey(String keyName, TransitKeyType type) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", type.wireValue());
        body.put("exportable", false);
        body.put("allow_plaintext_backup", false);
        client.write(paths.transitKey(keyName), body, paths.namespace());
        record("transit.key.create", keyName);
    }

    /** Sign {@code data}, returning Vault's {@code vault:v<n>:<sig>} signature string. */
    public String sign(String keyName, byte[] data) {
        Map<String, Object> response = client.write(
                paths.transitSign(keyName),
                Map.of("input", Base64.getEncoder().encodeToString(data)),
                paths.namespace());
        record("transit.sign", keyName);
        return string(response, "signature")
                .orElseThrow(() -> new VaultException("transit sign returned no signature for key " + keyName));
    }

    /**
     * Verify a signature.
     *
     * <p>Returns {@code false} when Vault's response is absent or malformed. An unparseable response
     * must never read as a successful verification.
     */
    public boolean verify(String keyName, byte[] data, String signature) {
        Map<String, Object> response = client.write(
                paths.transitVerify(keyName),
                Map.of("input", Base64.getEncoder().encodeToString(data), "signature", signature),
                paths.namespace());
        Object valid = data(response).get("valid");
        boolean ok = valid instanceof Boolean b && b;
        record("transit.verify", keyName, ok ? AuditOutcome.SUCCESS : AuditOutcome.FAILURE);
        return ok;
    }

    public String encrypt(String keyName, byte[] plaintext) {
        Map<String, Object> response = client.write(
                paths.transitEncrypt(keyName),
                Map.of("plaintext", Base64.getEncoder().encodeToString(plaintext)),
                paths.namespace());
        record("transit.encrypt", keyName);
        return string(response, "ciphertext")
                .orElseThrow(() -> new VaultException("transit encrypt returned no ciphertext for key " + keyName));
    }

    public byte[] decrypt(String keyName, String ciphertext) {
        Map<String, Object> response = client.write(
                paths.transitDecrypt(keyName),
                Map.of("ciphertext", ciphertext),
                paths.namespace());
        record("transit.decrypt", keyName);
        return Base64.getDecoder().decode(string(response, "plaintext")
                .orElseThrow(() -> new VaultException("transit decrypt returned no plaintext for key " + keyName)));
    }

    /**
     * Rotate to a new key version. Prior versions remain able to verify, which is what makes the
     * platform's overlapping-{@code kid} rotation (ADR-0007) safe.
     */
    public void rotate(String keyName) {
        client.write(paths.transitKeyRotate(keyName), Map.of(), paths.namespace());
        record("transit.key.rotate", keyName);
    }

    private void record(String action, String keyName) {
        record(action, keyName, AuditOutcome.SUCCESS);
    }

    private void record(String action, String keyName, AuditOutcome outcome) {
        if (audit == null) {
            return;
        }
        // Key NAME and operation only. Never the signature, ciphertext, plaintext or key material.
        audit.publish(AuditEvent.of("vault", action, outcome).target(keyName).build());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> data(Map<String, Object> response) {
        Object data = response == null ? null : response.get("data");
        return data instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    private static java.util.Optional<String> string(Map<String, Object> response, String field) {
        Object value = data(response).get(field);
        return value instanceof String s ? java.util.Optional.of(s) : java.util.Optional.empty();
    }
}
