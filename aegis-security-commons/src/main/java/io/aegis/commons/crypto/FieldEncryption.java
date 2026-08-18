package io.aegis.commons.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM authenticated encryption for sensitive values at rest (secrets, key material, seeds).
 *
 * <p>This is the shared, instance-based counterpart to the per-service static copies that already
 * exist in {@code mfa-webauthn-service} and {@code social-broker-service}. Those two use a static
 * key holder because a JPA {@code AttributeConverter} is instantiated by Hibernate rather than
 * Spring, which forces static state. Callers that encrypt <em>explicitly</em> in a service layer
 * (the authorization-server's tenant key store) have no such constraint, so this class is an
 * ordinary injectable bean with no static mutable state — easier to test and impossible to leave
 * half-initialised.
 *
 * <p><strong>Wire format</strong> — {@code v1:base64(iv || ciphertext || tag)} with a fresh 96-bit
 * random IV per value and a 128-bit tag, byte-compatible with the existing per-service copies so a
 * future consolidation needs no data migration. A stored value <em>without</em> the {@code v1:}
 * prefix is treated as legacy plaintext and returned as-is on read, so pre-existing rows keep
 * working; re-saving a row migrates it to ciphertext. New writes are always encrypted.
 *
 * <p><strong>Why GCM</strong> — the values protected here are attacker-relevant if tampered with,
 * not merely if read (a signing key swapped for one the attacker controls would let them mint
 * tokens). GCM authenticates as well as encrypts, so a modified ciphertext fails to decrypt rather
 * than silently yielding attacker-chosen plaintext.
 *
 * <p>Deliberately <em>not</em> auto-configured: a service that has nothing to encrypt must not be
 * forced to supply a key at startup. Declare it as a {@code @Bean} where it is needed.
 */
public final class FieldEncryption {

    /** Prefix marking a value as v1 AES-GCM ciphertext (distinguishes it from legacy plaintext). */
    public static final String PREFIX = "v1:";

    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int AES_256_KEY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;

    /**
     * @param keyBytes exactly 32 bytes (AES-256). The array is defensively copied; the caller should
     *                 zero its own copy afterwards.
     */
    public FieldEncryption(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != AES_256_KEY_BYTES) {
            throw new IllegalArgumentException("field encryption key must be 32 bytes (AES-256)");
        }
        this.key = new SecretKeySpec(Arrays.copyOf(keyBytes, keyBytes.length), "AES");
    }

    /** Build from a base64-encoded 32-byte key, zeroing the decoded material after use. */
    public static FieldEncryption fromBase64Key(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalArgumentException("field encryption key must not be blank");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("field encryption key must be valid base64", ex);
        }
        try {
            return new FieldEncryption(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /** Encrypt to {@code v1:base64(iv||ct)}. Returns {@code null} for {@code null}. */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_BYTES];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return PREFIX + Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            // Never include the plaintext or key in the message.
            throw new IllegalStateException("field encryption failed", e);
        }
    }

    /**
     * Decrypt a stored value. A value without the {@code v1:} prefix is legacy plaintext and is
     * returned unchanged. Throws if authenticated decryption fails — a tampered or wrong-key value
     * must never be silently accepted.
     */
    public String decrypt(String stored) {
        if (stored == null) {
            return null;
        }
        if (!stored.startsWith(PREFIX)) {
            return stored; // legacy plaintext row — re-saving migrates it
        }
        try {
            byte[] blob = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            if (blob.length <= IV_BYTES) {
                throw new IllegalArgumentException("ciphertext too short");
            }
            byte[] iv = Arrays.copyOf(blob, IV_BYTES);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] pt = cipher.doFinal(blob, IV_BYTES, blob.length - IV_BYTES);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("field decryption failed", e);
        }
    }

    /** True if the stored value is v1 ciphertext (as opposed to a legacy plaintext row). */
    public static boolean isEncrypted(String stored) {
        return stored != null && stored.startsWith(PREFIX);
    }
}
