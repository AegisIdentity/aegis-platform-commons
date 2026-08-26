package io.aegis.commons.vault;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
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
     * Sign for a JWS, returning the <b>raw</b> signature bytes.
     *
     * <p>Two details here are load-bearing and easy to get wrong.
     *
     * <p>First, the algorithm. A JWS header of {@code RS256} promises RSASSA-PKCS1-v1_5 over SHA-256.
     * Vault's transit engine defaults RSA signing to <b>PSS</b>, so omitting these parameters
     * produces a signature that no JWT verifier accepts — and the failure surfaces as "invalid token"
     * across every resource server rather than as an error here, which is a miserable thing to debug.
     *
     * <p>Second, the encoding. Vault returns {@code vault:v<n>:<base64>}; a JWS needs the raw bytes.
     * Leaving the prefix attached yields a token that looks perfectly well-formed and never verifies.
     */
    public byte[] signJws(String keyName, byte[] signingInput) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("input", Base64.getEncoder().encodeToString(signingInput));
        body.put("signature_algorithm", "pkcs1v15");
        body.put("hash_algorithm", "sha2-256");
        body.put("prehashed", false);

        Map<String, Object> response = client.write(paths.transitSign(keyName), body, paths.namespace());
        record("transit.sign", keyName);

        String signature = string(response, "signature")
                .orElseThrow(() -> new VaultException("transit sign returned no signature for key " + keyName));
        return decodeVaultSignature(signature, keyName);
    }

    /**
     * Strip Vault's {@code vault:v<n>:} envelope and decode the payload.
     *
     * @throws VaultException if the envelope is absent — better to fail at signing time than to emit
     *                        a token that silently never verifies.
     */
    private static byte[] decodeVaultSignature(String signature, String keyName) {
        int lastColon = signature.lastIndexOf(':');
        if (!signature.startsWith("vault:") || lastColon < 0) {
            throw new VaultException("unexpected transit signature format for key " + keyName);
        }
        return Base64.getDecoder().decode(signature.substring(lastColon + 1));
    }

    /** The latest public key version. */
    public VaultPublicKey publicKey(String keyName) {
        List<VaultPublicKey> versions = publicKeyVersions(keyName);
        if (versions.isEmpty()) {
            throw new VaultException("no public key for transit key " + keyName);
        }
        return versions.get(versions.size() - 1);
    }

    /**
     * Every public key version, oldest first.
     *
     * <p>All versions matter, not just the newest: overlapping-{@code kid} rotation (ADR-0007) means
     * a token signed by version 1 must still verify after the key rotates to version 2, so JWKS has
     * to publish both until the older tokens have expired.
     */
    public List<VaultPublicKey> publicKeyVersions(String keyName) {
        Map<String, Object> data = data(client.read(paths.transitKey(keyName), paths.namespace()));
        Object keys = data.get("keys");
        if (!(keys instanceof Map<?, ?> keyMap)) {
            return List.of();
        }

        List<VaultPublicKey> versions = new ArrayList<>();
        keyMap.forEach((version, detail) -> {
            if (detail instanceof Map<?, ?> fields && fields.get("public_key") instanceof String pem) {
                try {
                    versions.add(new VaultPublicKey(Integer.parseInt(String.valueOf(version)), pem));
                } catch (NumberFormatException ignored) {
                    // A non-numeric version key is not something Vault produces; skip rather than
                    // fail the whole read and lose the versions we can use.
                }
            }
        });
        versions.sort(Comparator.comparingInt(VaultPublicKey::version));
        return List.copyOf(versions);
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
